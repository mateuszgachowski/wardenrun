import Foundation

/// How wardenrun recognises the `bw` it is allowed to run (DESIGN 5.2, rule 1).
public enum BwPin: Equatable, Sendable {
    /// The signed GitHub-release binary at this absolute path, checked against a code
    /// requirement on this team before every run.
    case signedRelease(teamID: String, path: String)
}

public enum ConfigError: Error, Equatable {
    case unsupportedVersion(Int)
    /// The server is not plain HTTPS, or the URL carries credentials.
    case insecureServerURL
    /// The server URL cannot be used at all: unparseable, bad host or port, query or fragment.
    case invalidServerURL
    case missingField(String)
    /// The named field is present but not acceptable (shape, encoding or an absolute-path rule).
    case invalidValue(String)
    case emptyCollections
    case malformed
}

/// The settings that live inside the protected keychain item (DESIGN 5.8). Everything that
/// widens access is here, not in a file the agent can edit.
///
/// Errors name the field, never its value, and printing the config never shows the password.
public struct ProtectedConfig: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable, Sendable {
    public static let currentVersion = 1

    public let serverURL: URL
    public let accountEmail: String
    public let organizationID: String
    public let collectionIDs: [String]
    public let masterPassword: SecretBuffer
    public let bwPin: BwPin
    public let nodeExtraCACerts: String?
    public let httpsProxy: String?

    public init(serverURL: URL, accountEmail: String, organizationID: String, collectionIDs: [String],
                masterPassword: SecretBuffer, bwPin: BwPin,
                nodeExtraCACerts: String? = nil, httpsProxy: String? = nil) throws {
        let checkedURL = try Self.validatedServerURL(serverURL.absoluteString)
        guard !accountEmail.isEmpty else { throw ConfigError.missingField("account_email") }
        guard !organizationID.isEmpty else { throw ConfigError.missingField("organization_id") }
        guard Self.isSafeID(organizationID) else { throw ConfigError.invalidValue("organization_id") }
        guard !collectionIDs.isEmpty else { throw ConfigError.emptyCollections }
        guard collectionIDs.allSatisfy(Self.isSafeID) else { throw ConfigError.invalidValue("collection_ids") }
        guard masterPassword.count > 0 else { throw ConfigError.missingField("master_password") }
        // A password that is not valid UTF-8 would be silently rewritten by the JSON round trip.
        guard masterPassword.withUnsafeBytes({ String(bytes: Array($0), encoding: .utf8) != nil }) else {
            throw ConfigError.invalidValue("master_password")
        }
        let checkedPin: BwPin
        switch bwPin {
        case .signedRelease(let teamID, let path):
            // Later code builds a code requirement from this string, so its shape is fixed here.
            guard Self.isTeamID(teamID) else { throw ConfigError.invalidValue("team_id") }
            guard Self.isAbsolutePath(path) else { throw ConfigError.invalidValue("path") }
            checkedPin = bwPin
        }
        self.serverURL = checkedURL
        self.accountEmail = accountEmail
        self.organizationID = organizationID
        self.collectionIDs = collectionIDs
        self.masterPassword = masterPassword
        self.bwPin = checkedPin
        self.nodeExtraCACerts = nodeExtraCACerts
        self.httpsProxy = httpsProxy
    }

    /// The JSON that is stored in the keychain item. It contains the master password, so it is
    /// written straight into locked memory and never passes through a `String` or `Data`.
    public func encode() throws -> SecretBuffer {
        let pin: SecretJSONValue
        switch bwPin {
        case .signedRelease(let teamID, let path):
            pin = .object([("kind", .string("signed_release")), ("team_id", .string(teamID)), ("path", .string(path))])
        }
        var members: [(String, SecretJSONValue)] = [
            ("version", .integer(Self.currentVersion)),
            ("server_url", .string(serverURL.absoluteString)),
            ("account_email", .string(accountEmail)),
            ("organization_id", .string(organizationID)),
            ("collection_ids", .array(collectionIDs.map { .string($0) })),
            ("master_password", .secret(masterPassword)),
            ("bw_pin", pin),
        ]
        if let nodeExtraCACerts { members.append(("node_extra_ca_certs", .string(nodeExtraCACerts))) }
        if let httpsProxy { members.append(("https_proxy", .string(httpsProxy))) }
        return try SecretJSON.encode(.object(members))
    }

    /// Reads the blob with the byte scanner: the master password goes from the buffer into a new
    /// `SecretBuffer` without becoming a `String`. Unknown keys are ignored; a known key that
    /// appears twice, a value of the wrong type or any syntax error is `.malformed`.
    public static func decode(from blob: SecretBuffer) throws -> ProtectedConfig {
        let raw: RawConfig
        do {
            raw = try blob.withUnsafeBytes { try RawConfig.read($0) }
        } catch is JSONError {
            throw ConfigError.malformed
        }
        guard let version = raw.version else { throw ConfigError.missingField("version") }
        guard version == currentVersion else { throw ConfigError.unsupportedVersion(version) }
        guard let serverText = raw.serverURL else { throw ConfigError.missingField("server_url") }
        guard let email = raw.accountEmail else { throw ConfigError.missingField("account_email") }
        guard let organization = raw.organizationID else { throw ConfigError.missingField("organization_id") }
        guard let collections = raw.collectionIDs else { throw ConfigError.missingField("collection_ids") }
        guard let password = raw.masterPassword else { throw ConfigError.missingField("master_password") }
        guard let pin = raw.bwPin else { throw ConfigError.missingField("bw_pin") }
        let url = try validatedServerURL(serverText)
        return try ProtectedConfig(serverURL: url, accountEmail: email, organizationID: organization,
                                   collectionIDs: collections, masterPassword: password, bwPin: pin,
                                   nodeExtraCACerts: raw.nodeExtraCACerts, httpsProxy: raw.httpsProxy)
    }

    public var description: String {
        "ProtectedConfig(server: \(serverURL.absoluteString), collections: \(collectionIDs.count), password: <redacted>)"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(self, children: []) }

    // MARK: validation helpers

    /// Plain HTTPS only, checked on the raw text so macOS and Linux agree (Foundation's own URL
    /// parsing differs between them): ASCII without spaces or control characters (an
    /// internationalised name must be given as punycode), a real host, a port in 1...65535, no
    /// credentials, no query, no fragment. The scheme is stored lower case.
    static func validatedServerURL(_ text: String) throws -> URL {
        guard !text.isEmpty, text.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
              let separator = text.range(of: "://") else { throw ConfigError.invalidServerURL }
        let scheme = text[..<separator.lowerBound].lowercased()
        guard !scheme.isEmpty else { throw ConfigError.invalidServerURL }
        guard scheme == "https" else { throw ConfigError.insecureServerURL }
        let rest = String(text[separator.upperBound...])
        guard !rest.contains("?"), !rest.contains("#") else { throw ConfigError.invalidServerURL }
        let authority = String(rest.prefix { $0 != "/" })
        guard !authority.contains("@") else { throw ConfigError.insecureServerURL }

        let host: String
        var portText: Substring?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { throw ConfigError.invalidServerURL }
            host = String(authority[authority.index(after: authority.startIndex)..<close])
            let after = authority[authority.index(after: close)...]
            if !after.isEmpty {
                guard after.hasPrefix(":") else { throw ConfigError.invalidServerURL }
                portText = after.dropFirst()
            }
        } else {
            let parts = authority.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count <= 2 else { throw ConfigError.invalidServerURL }
            host = String(parts[0])
            if parts.count == 2 { portText = parts[1] }
        }
        guard isValidHost(host) else { throw ConfigError.invalidServerURL }
        if let portText {
            guard !portText.isEmpty, portText.utf8.count <= 5, portText.utf8.allSatisfy(isDigit),
                  let port = Int(portText), (1...65535).contains(port) else { throw ConfigError.invalidServerURL }
        }
        guard let url = URL(string: "https://" + rest) else { throw ConfigError.invalidServerURL }
        return url
    }

    private static func isValidHost(_ host: String) -> Bool {
        if host.contains(":") {   // an IPv6 literal, brackets already removed
            return host.utf8.count >= 2 && host.utf8.allSatisfy { isHexDigit($0) || $0 == UInt8(ascii: ":") || $0 == UInt8(ascii: ".") }
        }
        guard !host.isEmpty, host.utf8.count <= 253 else { return false }
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.utf8.allSatisfy { isAlphanumeric($0) || $0 == UInt8(ascii: "-") }
        }
    }

    private static func isSafeID(_ text: String) -> Bool {
        (1...64).contains(text.utf8.count) && text.utf8.allSatisfy { isAlphanumeric($0) || $0 == UInt8(ascii: "-") }
    }

    private static func isTeamID(_ text: String) -> Bool {
        text.utf8.count == 10 && text.utf8.allSatisfy { ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z")) || isDigit($0) }
    }

    private static func isAbsolutePath(_ text: String) -> Bool {
        text.hasPrefix("/") && text.utf8.allSatisfy { $0 >= 0x20 && $0 != 0x7F }
    }

    private static func isDigit(_ byte: UInt8) -> Bool { byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9") }

    private static func isAlphanumeric(_ byte: UInt8) -> Bool {
        isDigit(byte) || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        isDigit(byte) || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "F")) || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
    }

    /// What the blob says, field by field, before any validation.
    private struct RawConfig {
        var version: Int?
        var serverURL: String?
        var accountEmail: String?
        var organizationID: String?
        var collectionIDs: [String]?
        var masterPassword: SecretBuffer?
        var bwPin: BwPin?
        var nodeExtraCACerts: String?
        var httpsProxy: String?

        static func read(_ bytes: UnsafeRawBufferPointer) throws -> RawConfig {
            var cursor = JSONCursor(bytes)
            var raw = RawConfig()
            var seen = Set<String>()
            guard try cursor.kind() == .object else { throw ConfigError.malformed }
            try cursor.members { key, value in
                let name = String(decoding: key, as: UTF8.self)
                switch name {
                case "version", "server_url", "account_email", "organization_id", "collection_ids",
                     "master_password", "bw_pin", "node_extra_ca_certs", "https_proxy":
                    guard seen.insert(name).inserted else { throw ConfigError.malformed }
                default:
                    try value.skipValue()
                    return
                }
                switch name {
                case "version": raw.version = try readInteger(&value, in: bytes)
                case "server_url": raw.serverURL = try readText(&value)
                case "account_email": raw.accountEmail = try readText(&value)
                case "organization_id": raw.organizationID = try readText(&value)
                case "collection_ids": raw.collectionIDs = try readTexts(&value)
                case "master_password":
                    guard try value.kind() == .string else { throw ConfigError.malformed }
                    raw.masterPassword = try value.secretString()
                case "bw_pin": raw.bwPin = try readPin(&value)
                case "node_extra_ca_certs": raw.nodeExtraCACerts = try readText(&value)
                default: raw.httpsProxy = try readText(&value)
                }
            }
            try cursor.finish()
            return raw
        }

        private static func readText(_ value: inout JSONCursor) throws -> String {
            guard try value.kind() == .string else { throw ConfigError.malformed }
            return String(decoding: try value.string(), as: UTF8.self)
        }

        private static func readTexts(_ value: inout JSONCursor) throws -> [String] {
            guard try value.kind() == .array else { throw ConfigError.malformed }
            var items: [String] = []
            try value.elements { _, element in items.append(try readText(&element)) }
            return items
        }

        private static func readInteger(_ value: inout JSONCursor, in bytes: UnsafeRawBufferPointer) throws -> Int {
            guard try value.kind() == .number else { throw ConfigError.malformed }
            let range = try value.skipValue()
            guard let number = Int(String(decoding: bytes[range], as: UTF8.self)) else { throw ConfigError.malformed }
            return number
        }

        private static func readPin(_ value: inout JSONCursor) throws -> BwPin {
            guard try value.kind() == .object else { throw ConfigError.malformed }
            var fields: [String: String] = [:]
            try value.members { key, member in
                let name = String(decoding: key, as: UTF8.self)
                if try member.kind() == .string {
                    guard fields.updateValue(try readText(&member), forKey: name) == nil else { throw ConfigError.malformed }
                } else {
                    try member.skipValue()
                }
            }
            switch fields["kind"] {
            case "signed_release":
                guard let team = fields["team_id"], let path = fields["path"] else { throw ConfigError.malformed }
                return .signedRelease(teamID: team, path: path)
            default:
                throw ConfigError.malformed
            }
        }
    }
}

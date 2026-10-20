import Foundation

/// How wardenrun recognises the `bw` it is allowed to run (DESIGN 5.2, rule 1).
public enum BwPin: Codable, Equatable, Sendable {
    /// The signed GitHub-release binary at this absolute path, checked against a code
    /// requirement on this team before every run.
    case signedRelease(teamID: String, path: String)

    private enum Keys: String, CodingKey {
        case kind
        case teamID = "team_id"
        case path
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "signed_release":
            self = .signedRelease(teamID: try c.decode(String.self, forKey: .teamID),
                                  path: try c.decode(String.self, forKey: .path))
        default:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown pin kind")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .signedRelease(let teamID, let path):
            try c.encode("signed_release", forKey: .kind)
            try c.encode(teamID, forKey: .teamID)
            try c.encode(path, forKey: .path)
        }
    }
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

    /// The JSON that is stored in the keychain item. It contains the master password.
    public func encode() throws -> Data {
        let wire = Wire(version: Self.currentVersion, serverURL: serverURL.absoluteString,
                        accountEmail: accountEmail, organizationID: organizationID,
                        collectionIDs: collectionIDs,
                        masterPassword: masterPassword.withUnsafeBytes { String(decoding: $0, as: UTF8.self) },
                        bwPin: bwPin, nodeExtraCACerts: nodeExtraCACerts, httpsProxy: httpsProxy)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(wire)
    }

    public static func decode(from data: Data) throws -> ProtectedConfig {
        guard let wire = try? JSONDecoder().decode(Wire.self, from: data) else { throw ConfigError.malformed }
        guard let version = wire.version else { throw ConfigError.missingField("version") }
        guard version == currentVersion else { throw ConfigError.unsupportedVersion(version) }
        guard let serverText = wire.serverURL else { throw ConfigError.missingField("server_url") }
        guard let email = wire.accountEmail else { throw ConfigError.missingField("account_email") }
        guard let organization = wire.organizationID else { throw ConfigError.missingField("organization_id") }
        guard let collections = wire.collectionIDs else { throw ConfigError.missingField("collection_ids") }
        guard let password = wire.masterPassword else { throw ConfigError.missingField("master_password") }
        guard let pin = wire.bwPin else { throw ConfigError.missingField("bw_pin") }
        let url = try validatedServerURL(serverText)
        return try ProtectedConfig(serverURL: url, accountEmail: email, organizationID: organization,
                                   collectionIDs: collections, masterPassword: SecretBuffer(copying: Array(password.utf8)),
                                   bwPin: pin, nodeExtraCACerts: wire.nodeExtraCACerts, httpsProxy: wire.httpsProxy)
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


    private struct Wire: Codable {
        var version: Int?
        var serverURL: String?
        var accountEmail: String?
        var organizationID: String?
        var collectionIDs: [String]?
        var masterPassword: String?
        var bwPin: BwPin?
        var nodeExtraCACerts: String?
        var httpsProxy: String?

        enum CodingKeys: String, CodingKey {
            case version
            case serverURL = "server_url"
            case accountEmail = "account_email"
            case organizationID = "organization_id"
            case collectionIDs = "collection_ids"
            case masterPassword = "master_password"
            case bwPin = "bw_pin"
            case nodeExtraCACerts = "node_extra_ca_certs"
            case httpsProxy = "https_proxy"
        }
    }
}

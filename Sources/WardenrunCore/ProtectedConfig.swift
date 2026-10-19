import Foundation

/// How wardenrun recognises the `bw` it is allowed to run (DESIGN 5.2, rule 1).
public enum BwPin: Codable, Equatable, Sendable {
    /// The signed GitHub-release binary, checked against a code requirement on this team.
    case signedRelease(teamID: String)
    /// Homebrew's Node build: absolute paths of `node` and the script, with their SHA-256.
    case nodeScript(nodePath: String, nodeSHA256: String, scriptPath: String, scriptSHA256: String)

    private enum Keys: String, CodingKey {
        case kind
        case teamID = "team_id"
        case nodePath = "node_path"
        case nodeSHA256 = "node_sha256"
        case scriptPath = "script_path"
        case scriptSHA256 = "script_sha256"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "signed_release":
            self = .signedRelease(teamID: try c.decode(String.self, forKey: .teamID))
        case "node_script":
            self = .nodeScript(nodePath: try c.decode(String.self, forKey: .nodePath),
                               nodeSHA256: try c.decode(String.self, forKey: .nodeSHA256),
                               scriptPath: try c.decode(String.self, forKey: .scriptPath),
                               scriptSHA256: try c.decode(String.self, forKey: .scriptSHA256))
        default:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c, debugDescription: "unknown pin kind")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .signedRelease(let teamID):
            try c.encode("signed_release", forKey: .kind)
            try c.encode(teamID, forKey: .teamID)
        case .nodeScript(let nodePath, let nodeSHA256, let scriptPath, let scriptSHA256):
            try c.encode("node_script", forKey: .kind)
            try c.encode(nodePath, forKey: .nodePath)
            try c.encode(nodeSHA256, forKey: .nodeSHA256)
            try c.encode(scriptPath, forKey: .scriptPath)
            try c.encode(scriptSHA256, forKey: .scriptSHA256)
        }
    }
}

public enum ConfigError: Error, Equatable {
    case unsupportedVersion(Int)
    case insecureServerURL
    case missingField(String)
    case emptyCollections
    case invalidHash(String)
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
        guard serverURL.scheme?.lowercased() == "https", let host = serverURL.host, !host.isEmpty,
              serverURL.user == nil, serverURL.password == nil else { throw ConfigError.insecureServerURL }
        guard !accountEmail.isEmpty else { throw ConfigError.missingField("account_email") }
        guard !organizationID.isEmpty else { throw ConfigError.missingField("organization_id") }
        guard !collectionIDs.isEmpty else { throw ConfigError.emptyCollections }
        guard masterPassword.count > 0 else { throw ConfigError.missingField("master_password") }
        switch bwPin {
        case .signedRelease(let teamID):
            guard !teamID.isEmpty else { throw ConfigError.missingField("team_id") }
        case .nodeScript(_, let nodeSHA256, _, let scriptSHA256):
            guard Self.isSHA256Hex(nodeSHA256) else { throw ConfigError.invalidHash("node_sha256") }
            guard Self.isSHA256Hex(scriptSHA256) else { throw ConfigError.invalidHash("script_sha256") }
        }
        self.serverURL = serverURL
        self.accountEmail = accountEmail
        self.organizationID = organizationID
        self.collectionIDs = collectionIDs
        self.masterPassword = masterPassword
        self.bwPin = bwPin
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
        guard let url = URL(string: serverText) else { throw ConfigError.insecureServerURL }
        return try ProtectedConfig(serverURL: url, accountEmail: email, organizationID: organization,
                                   collectionIDs: collections, masterPassword: SecretBuffer(copying: Array(password.utf8)),
                                   bwPin: pin, nodeExtraCACerts: wire.nodeExtraCACerts, httpsProxy: wire.httpsProxy)
    }

    public var description: String {
        "ProtectedConfig(server: \(serverURL.absoluteString), collections: \(collectionIDs.count), password: <redacted>)"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(self, children: []) }

    private static func isSHA256Hex(_ text: String) -> Bool {
        text.utf8.count == 64 && Hex.decode(text) != nil
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

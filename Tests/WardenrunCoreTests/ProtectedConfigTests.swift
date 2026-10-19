import Foundation
import Testing
@testable import WardenrunCore

struct ProtectedConfigTests {
    private static let password = "correct-horse-battery-staple"
    private static let hash = String(repeating: "ab", count: 32)

    /// A valid blob as a dictionary, so each test can break one thing.
    private func blob(_ change: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var object: [String: Any] = [
            "version": 1,
            "server_url": "https://vault.example:8443/base",
            "account_email": "agent@example.org",
            "organization_id": "org-1",
            "collection_ids": ["col-1", "col-2"],
            "master_password": Self.password,
            "bw_pin": ["kind": "signed_release", "team_id": "LTZ2PFU5D6"],
        ]
        change(&object)
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func passwordText(_ config: ProtectedConfig) -> String {
        config.masterPassword.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
    }

    // MARK: round trip

    @Test func decodesAValidBlob() throws {
        let config = try ProtectedConfig.decode(from: blob())
        #expect(config.serverURL.absoluteString == "https://vault.example:8443/base")
        #expect(config.accountEmail == "agent@example.org")
        #expect(config.organizationID == "org-1")
        #expect(config.collectionIDs == ["col-1", "col-2"])
        #expect(passwordText(config) == Self.password)
        #expect(config.bwPin == .signedRelease(teamID: "LTZ2PFU5D6"))
        #expect(config.nodeExtraCACerts == nil)
        #expect(config.httpsProxy == nil)
    }

    @Test func roundTripKeepsEveryFieldForBothPinKinds() throws {
        let pins: [BwPin] = [
            .signedRelease(teamID: "LTZ2PFU5D6"),
            .nodeScript(nodePath: "/opt/node/bin/node", nodeSHA256: Self.hash,
                        scriptPath: "/opt/bw/bw.js", scriptSHA256: String(repeating: "cd", count: 32)),
        ]
        for pin in pins {
            let original = try ProtectedConfig(
                serverURL: try #require(URL(string: "https://vault.example")), accountEmail: "a@b.example",
                organizationID: "o", collectionIDs: ["c"], masterPassword: SecretBuffer(copying: Array(Self.password.utf8)),
                bwPin: pin, nodeExtraCACerts: "/ca.pem", httpsProxy: "https://p:3128")
            let copy = try ProtectedConfig.decode(from: original.encode())
            #expect(copy.serverURL == original.serverURL)
            #expect(copy.accountEmail == original.accountEmail)
            #expect(copy.organizationID == original.organizationID)
            #expect(copy.collectionIDs == original.collectionIDs)
            #expect(passwordText(copy) == Self.password)
            #expect(copy.bwPin == pin)
            #expect(copy.nodeExtraCACerts == "/ca.pem")
            #expect(copy.httpsProxy == "https://p:3128")
        }
    }

    @Test func encodeWritesTheVersionAndThePasswordBecauseThatIsTheBlobToStore() throws {
        let config = try ProtectedConfig.decode(from: blob())
        let object = try #require(JSONSerialization.jsonObject(with: config.encode()) as? [String: Any])
        #expect(object["version"] as? Int == ProtectedConfig.currentVersion)
        #expect(object["master_password"] as? String == Self.password)
    }

    // MARK: validation

    @Test(arguments: ["http://127.0.0.1:8080", "http://vault.example", "ftp://vault.example", "https://",
                      "https://u:p@vault.example", "not a url", ""])
    func onlyPlainHTTPSServersAreAccepted(url: String) throws {
        #expect(throws: ConfigError.insecureServerURL) {
            try ProtectedConfig.decode(from: blob { $0["server_url"] = url })
        }
    }

    @Test func httpsIsAcceptedInAnyCaseAndWithAPortAndPath() throws {
        for url in ["https://vault.example", "HTTPS://Vault.Example", "https://vault.example:8443/base"] {
            _ = try ProtectedConfig.decode(from: blob { $0["server_url"] = url })
        }
    }

    @Test func rejectsAnUnknownVersion() {
        #expect(throws: ConfigError.unsupportedVersion(2)) { try ProtectedConfig.decode(from: blob { $0["version"] = 2 }) }
    }

    @Test(arguments: ["version", "server_url", "account_email", "organization_id", "collection_ids",
                      "master_password", "bw_pin"])
    func rejectsAMissingRequiredField(key: String) {
        #expect(throws: ConfigError.missingField(key)) { try ProtectedConfig.decode(from: blob { $0[key] = nil }) }
    }

    @Test func rejectsEmptyCollectionsAndAnEmptyPassword() {
        #expect(throws: ConfigError.emptyCollections) { try ProtectedConfig.decode(from: blob { $0["collection_ids"] = [String]() }) }
        #expect(throws: ConfigError.missingField("master_password")) { try ProtectedConfig.decode(from: blob { $0["master_password"] = "" }) }
    }

    @Test func rejectsPinnedHashesThatAreNotSHA256Hex() {
        for bad in ["abc", String(repeating: "g", count: 64), String(repeating: "ab", count: 33)] {
            #expect(throws: ConfigError.invalidHash("node_sha256")) {
                try ProtectedConfig.decode(from: blob {
                    $0["bw_pin"] = ["kind": "node_script", "node_path": "/n", "node_sha256": bad,
                                    "script_path": "/s", "script_sha256": Self.hash]
                })
            }
            #expect(throws: ConfigError.invalidHash("script_sha256")) {
                try ProtectedConfig.decode(from: blob {
                    $0["bw_pin"] = ["kind": "node_script", "node_path": "/n", "node_sha256": Self.hash,
                                    "script_path": "/s", "script_sha256": bad]
                })
            }
        }
    }

    @Test func rejectsGarbage() {
        #expect(throws: ConfigError.malformed) { try ProtectedConfig.decode(from: Data("not json".utf8)) }
        #expect(throws: ConfigError.malformed) { try ProtectedConfig.decode(from: Data("[1,2]".utf8)) }
        #expect(throws: ConfigError.malformed) { try ProtectedConfig.decode(from: blob { $0["collection_ids"] = "col-1" }) }
        #expect(throws: ConfigError.malformed) { try ProtectedConfig.decode(from: blob { $0["bw_pin"] = ["kind": "mystery"] }) }
    }

    // MARK: the password never leaks through printing or errors

    @Test func theMasterPasswordNeverAppearsInDescriptionsOrDumps() throws {
        let config = try ProtectedConfig.decode(from: blob())
        var dumped = ""
        dump(config, to: &dumped)
        for text in ["\(config)", String(reflecting: config), dumped] {
            #expect(!text.contains(Self.password))
            #expect(!text.contains("horse"))
        }
    }

    @Test func noErrorEchoesThePasswordOrTheServerCredentials() throws {
        let failures: [Data] = [
            try blob { $0["organization_id"] = nil },
            try blob { $0["server_url"] = "https://user:hunter2@vault.example" },
            try blob { $0["collection_ids"] = [String]() },
            try blob { $0["version"] = 9 },
        ]
        for data in failures {
            do { _ = try ProtectedConfig.decode(from: data); Issue.record("expected a failure") } catch {
                for text in ["\(error)", String(reflecting: error), (error as NSError).localizedDescription] {
                    #expect(!text.contains(Self.password))
                    #expect(!text.contains("hunter2"))
                }
            }
        }
    }
}

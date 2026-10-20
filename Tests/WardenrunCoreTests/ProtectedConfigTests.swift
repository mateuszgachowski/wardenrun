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
            "bw_pin": ["kind": "signed_release", "team_id": "LTZ2PFU5D6", "path": "/opt/wardenrun/bw"],
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
        #expect(config.bwPin == .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/wardenrun/bw"))
        #expect(config.nodeExtraCACerts == nil)
        #expect(config.httpsProxy == nil)
    }

    @Test func roundTripKeepsEveryField() throws {
        let pins: [BwPin] = [.signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/wardenrun/bw")]
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

    @Test(arguments: ["http://127.0.0.1:8080", "http://vault.example", "ftp://vault.example",
                      "https://u:p@vault.example", "https://user@vault.example"])
    func onlyPlainHTTPSServersAreAccepted(url: String) throws {
        #expect(throws: ConfigError.insecureServerURL) {
            try ProtectedConfig.decode(from: blob { $0["server_url"] = url })
        }
    }

    @Test(arguments: ["", "https://", "not a url", "https://vault example.com", "https://vault.example\n",
                      "https://vault.example/a b", "https://host:99999", "https://host:0", "https://-/",
                      "https://-a.example", "https://a-.example", "https://%2F/", "https://vault..example",
                      "https://vault.example/path?q=1", "https://vault.example/#frag", "https://vault.example/?",
                      "https://bücher.example", "vault.example"])
    func malformedServerURLsAreRejected(url: String) throws {
        #expect(throws: ConfigError.invalidServerURL) {
            try ProtectedConfig.decode(from: blob { $0["server_url"] = url })
        }
    }

    @Test func httpsIsAcceptedInAnyCaseWithAPortAPathAndIPLiterals() throws {
        for url in ["https://vault.example", "https://vault.example:8443/base", "https://vault.example/", "https://10.1.2.3:8443",
                    "https://[::1]:8443/", "https://xn--bcher-kva.example", "https://localhost"] {
            _ = try ProtectedConfig.decode(from: blob { $0["server_url"] = url })
        }
        let upper = try ProtectedConfig.decode(from: blob { $0["server_url"] = "HTTPS://Vault.Example/x" })
        #expect(upper.serverURL.scheme == "https")
    }

    @Test func theDirectInitializerAppliesTheSameURLRules() throws {
        for text in ["http://vault.example", "https://vault.example/?q=1"] {
            let url = try #require(URL(string: text))
            #expect(throws: (any Error).self) {
                try ProtectedConfig(serverURL: url, accountEmail: "a@b.example", organizationID: "o", collectionIDs: ["c"],
                                    masterPassword: SecretBuffer(copying: [1, 2, 3]), bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/wardenrun/bw"))
            }
        }
    }

    @Test(arguments: ["org 1", "org/1", "org\n1", "", String(repeating: "a", count: 65)])
    func organizationIDsHaveAConservativeShape(id: String) throws {
        let expected: ConfigError = id.isEmpty ? .missingField("organization_id") : .invalidValue("organization_id")
        #expect(throws: expected) { try ProtectedConfig.decode(from: blob { $0["organization_id"] = id }) }
    }

    @Test func collectionIDsMustAllBeNonEmptyAndConservative() {
        for bad in [[""], ["col-1", ""], ["col 1"], ["col-1", "a/b"]] {
            #expect(throws: ConfigError.invalidValue("collection_ids")) {
                try ProtectedConfig.decode(from: blob { $0["collection_ids"] = bad })
            }
        }
    }

    @Test(arguments: ["", "ltz2pfu5d6", "LTZ2PFU5D", "LTZ2PFU5D6X", "x\" or anchor apple", "LTZ2PFU5D!"])
    func theTeamIDMustBeTenUppercaseLettersOrDigits(team: String) {
        #expect(throws: ConfigError.invalidValue("team_id")) {
            try ProtectedConfig.decode(from: blob { $0["bw_pin"] = ["kind": "signed_release", "team_id": team, "path": "/opt/wardenrun/bw"] })
        }
    }

    @Test func theSignedReleasePathMustBeAbsolute() {
        for bad in ["bw", "./bw", "", "~/bin/bw"] {
            #expect(throws: ConfigError.invalidValue("path"), "\(bad)") {
                try ProtectedConfig.decode(from: blob {
                    $0["bw_pin"] = ["kind": "signed_release", "team_id": "LTZ2PFU5D6", "path": bad]
                })
            }
        }
    }

    @Test func aSignedReleasePinWithoutAPathIsMalformed() {
        #expect(throws: ConfigError.malformed) {
            try ProtectedConfig.decode(from: blob { $0["bw_pin"] = ["kind": "signed_release", "team_id": "LTZ2PFU5D6"] })
        }
    }

    @Test func theNodeBuildOfBwIsNotAcceptedAsAPin() {
        // `bw.js` loads node_modules, chunk files and wasm that no hash of `node` + `bw.js` covers.
        #expect(throws: ConfigError.malformed) {
            try ProtectedConfig.decode(from: blob {
                $0["bw_pin"] = ["kind": "node_script", "node_path": "/n", "node_sha256": Self.hash,
                                "script_path": "/s", "script_sha256": Self.hash]
            })
        }
    }

    @Test func aMasterPasswordThatIsNotUTF8IsRejectedInsteadOfSilentlyChanged() throws {
        let url = try #require(URL(string: "https://vault.example"))
        #expect(throws: ConfigError.invalidValue("master_password")) {
            try ProtectedConfig(serverURL: url, accountEmail: "a@b.example", organizationID: "o", collectionIDs: ["c"],
                                masterPassword: SecretBuffer(copying: [0x61, 0xFF, 0x62, 0x63]),
                                bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/wardenrun/bw"))
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

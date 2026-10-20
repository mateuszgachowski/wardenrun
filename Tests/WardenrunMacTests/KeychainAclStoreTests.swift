#if canImport(Darwin)
import Foundation
import Security
import Testing
import WardenrunCore
@testable import WardenrunMac

/// A throw-away file keychain; deleted with its file when the value goes away. The user's login
/// keychain is never touched.
private final class TempKeychain {
    let path: String
    init() throws {
        path = (NSTemporaryDirectory() as NSString).appendingPathComponent("wardenrun-test-\(UUID().uuidString).keychain")
        try KeychainAclStore.createTemporaryKeychain(at: path)
    }
    deinit { KeychainAclStore.deleteTemporaryKeychain(at: path) }

    func store(service: String = "wardenrun-test") -> KeychainAclStore {
        KeychainAclStore(service: service, account: "protected-config", keychainPath: path)
    }

    /// The raw bytes of the item, read the way any program that is allowed to would.
    func rawBlob(service: String = "wardenrun-test") -> Data? {
        var keychain: SecKeychain?
        guard SecKeychainOpen(path, &keychain) == errSecSuccess, let keychain else { return nil }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: "protected-config", kSecReturnData as String: true,
            kSecMatchSearchList as String: [keychain] as CFArray,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    func itemCount(service: String = "wardenrun-test") -> Int {
        var keychain: SecKeychain?
        guard SecKeychainOpen(path, &keychain) == errSecSuccess, let keychain else { return -1 }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true,
            kSecMatchSearchList as String: [keychain] as CFArray,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return 0 }
        return (out as? [[String: Any]])?.count ?? -1
    }
}

private func sampleConfig(password: String = "correct-horse-battery-staple") throws -> ProtectedConfig {
    try ProtectedConfig(serverURL: try #require(URL(string: "https://vault.example:8443")), accountEmail: "agent@example.org",
                        organizationID: "org-1", collectionIDs: ["col-1", "col-2"],
                        masterPassword: SecretBuffer(copying: Array(password.utf8)),
                        bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/wardenrun/bw"),
                        nodeExtraCACerts: "/ca.pem", httpsProxy: "https://p:3128")
}

private func text(_ buffer: SecretBuffer) -> String { buffer.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }

@Suite(.serialized) struct KeychainAclStoreTests {
    @Test func savedConfigLoadsBackWithEveryField() throws {
        let keychain = try TempKeychain()
        let store = keychain.store()
        try store.save(try sampleConfig())
        let loaded = try #require(try store.load())
        #expect(loaded.serverURL.absoluteString == "https://vault.example:8443")
        #expect(loaded.accountEmail == "agent@example.org")
        #expect(loaded.organizationID == "org-1")
        #expect(loaded.collectionIDs == ["col-1", "col-2"])
        #expect(text(loaded.masterPassword) == "correct-horse-battery-staple")
        #expect(loaded.bwPin == .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/wardenrun/bw"))
        #expect(loaded.nodeExtraCACerts == "/ca.pem")
        #expect(loaded.httpsProxy == "https://p:3128")
    }

    @Test func loadFromAnEmptyKeychainIsNil() throws {
        let keychain = try TempKeychain()
        #expect(try keychain.store().load() == nil)
    }

    @Test func saveTwiceReplacesTheItem() throws {
        let keychain = try TempKeychain()
        let store = keychain.store()
        try store.save(try sampleConfig(password: "first-password"))
        try store.save(try sampleConfig(password: "second-password"))
        #expect(keychain.itemCount() == 1)
        #expect(text(try #require(try store.load()).masterPassword) == "second-password")
    }

    @Test func eraseRemovesAndSecondEraseIsHarmless() throws {
        let keychain = try TempKeychain()
        let store = keychain.store()
        try store.save(try sampleConfig())
        try store.erase()
        #expect(try store.load() == nil)
        #expect(keychain.itemCount() == 0)
        try store.erase()
    }

    @Test func theBlobInTheKeychainIsTheEncodedConfig() throws {
        let keychain = try TempKeychain()
        try keychain.store().save(try sampleConfig())
        let blob = try #require(keychain.rawBlob())
        let object = try #require(JSONSerialization.jsonObject(with: blob) as? [String: Any])
        #expect(object["version"] as? Int == ProtectedConfig.currentVersion)
        #expect(object["master_password"] as? String == "correct-horse-battery-staple")
        #expect(object["organization_id"] as? String == "org-1")
    }

    @Test func itemsOfOtherServicesAreNeitherReadNorTouched() throws {
        let keychain = try TempKeychain()
        try keychain.store(service: "other").save(try sampleConfig(password: "other-password"))
        let mine = keychain.store()
        #expect(try mine.load() == nil)
        try mine.save(try sampleConfig(password: "mine-password"))
        try mine.erase()
        #expect(text(try #require(try keychain.store(service: "other").load()).masterPassword) == "other-password")
    }

    @Test func userInteractionIsOffDuringEveryCallAndRestoredAfterwards() throws {
        let keychain = try TempKeychain()
        let store = keychain.store()
        var seen: [Bool] = []
        store.duringCall = {
            var allowed: DarwinBoolean = true
            SecKeychainGetUserInteractionAllowed(&allowed)
            seen.append(allowed.boolValue)
        }
        SecKeychainSetUserInteractionAllowed(true)   // a known starting point, whatever ran before
        try store.save(try sampleConfig())
        _ = try store.load()
        try store.erase()
        var after: DarwinBoolean = false
        SecKeychainGetUserInteractionAllowed(&after)
        #expect(seen.count >= 3 && !seen.contains(true), "interaction was allowed during a call: \(seen)")
        #expect(after.boolValue, "the interaction setting was not put back")
    }

    @Test func aCorruptBlobIsUnreadableWithAFixedMessageAndNoContent() throws {
        let keychain = try TempKeychain()
        let store = keychain.store()
        try store.save(try sampleConfig())
        // Overwrite the item with garbage that contains a recognisable marker.
        try keychain.overwrite(with: Data("not json SECRET-MARKER-123".utf8))
        do {
            _ = try store.load()
            Issue.record("a corrupt blob must not load")
        } catch let error as StoreError {
            #expect(error == .unreadable(reason: "the stored item is damaged; run wardenrun setup again"))
            #expect(!"\(error)".contains("SECRET-MARKER"))
        }
    }

    @Test func errorsNeverContainTheBlob() throws {
        let keychain = try TempKeychain()
        let store = keychain.store()
        try store.save(try sampleConfig(password: "pa55-w0rd-MARKER"))
        try keychain.overwrite(with: Data("{\"version\":1,\"master_password\":\"pa55-w0rd-MARKER\"".utf8))   // cut off
        do {
            _ = try store.load()
            Issue.record("a truncated blob must not load")
        } catch {
            #expect(!"\(error)".contains("MARKER") && !String(reflecting: error).contains("MARKER"))
        }
    }

    @Test func tierDescriptionSaysWhoEnforcesWhat() {
        let description = KeychainAclStore().tierDescription
        #expect(description == "B: item readable only by the signed wardenrun binary; approval enforced by wardenrun")
        #expect(!description.lowercased().contains("touch id protected"))
    }
}

extension TempKeychain {
    /// Replaces the stored bytes in place (same service and account), for the corruption tests.
    fileprivate func overwrite(with data: Data) throws {
        var keychain: SecKeychain?
        try #require(SecKeychainOpen(path, &keychain) == errSecSuccess)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "wardenrun-test",
            kSecAttrAccount as String: "protected-config",
            kSecMatchSearchList as String: [try #require(keychain)] as CFArray,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        try #require(status == errSecSuccess, "SecItemUpdate \(status)")
    }
}
#endif

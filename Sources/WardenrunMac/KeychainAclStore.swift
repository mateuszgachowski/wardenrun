#if canImport(Darwin)
import Foundation
import Security
import WardenrunCore

/// Tier B (DESIGN 3.4): one generic-password item in a file-based keychain whose access list
/// names only this binary. The system keeps the designated requirement of a signed binary, so a
/// later build signed with the same certificate can read the item and any other program cannot,
/// not even one of the same user. The Touch ID gate is wardenrun's own code; this item does not
/// ask for a fingerprint, and nothing here may suggest that it does.
///
/// File-based keychain calls are deprecated by Apple but still the only way to give an item an
/// access list; `SecKeychainSetUserInteractionAllowed(false)` and the `...UIFail` flag keep every
/// call from ever showing a dialog (an agent cannot click one, and a dialog would hide the cause).
public final class KeychainAclStore: SecretStore, @unchecked Sendable {
    private let service: String
    private let account: String
    private let keychainPath: String?

    /// Test hook: runs inside every call, while user interaction is off.
    var duringCall: (() -> Void)?

    private static let temporaryKeychainPassword = "wardenrun-test-keychain"
    private static let interactionLock = NSLock()
    private static let notReadable = "the item is not readable by this binary; run wardenrun setup again"
    private static let damaged = "the stored item is damaged; run wardenrun setup again"

    public init(service: String = "wardenrun", account: String = "protected-config", keychainPath: String? = nil) {
        self.service = service
        self.account = account
        self.keychainPath = keychainPath
    }

    public var tierDescription: String {
        "B: item readable only by the signed wardenrun binary; approval enforced by wardenrun"
    }

    // MARK: SecretStore

    public func load() throws -> ProtectedConfig? {
        try withoutInteraction { keychain in
            var query = baseQuery(keychain)
            query[kSecReturnData as String] = true
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
            var out: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &out)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess, let data = out, CFGetTypeID(data) == CFDataGetTypeID() else {
                throw StoreError.unreadable(reason: Self.readFailure(status))
            }
            let bytes = data as! CFData
            let length = CFDataGetLength(bytes)
            // The CFData was just made for this call and nobody else holds it, so it may be zeroed
            // once the locked copy exists. The system's own copies are beyond reach.
            defer {
                if let pointer = CFDataGetBytePtr(bytes) { memset_s(UnsafeMutableRawPointer(mutating: pointer), length, 0, length) }
            }
            let blob = SecretBuffer(count: length) { destination in
                if let from = CFDataGetBytePtr(bytes), let to = destination.baseAddress, length > 0 { memcpy(to, from, length) }
            }
            defer { blob.wipe() }
            do {
                return try ProtectedConfig.decode(from: blob)
            } catch {
                throw StoreError.unreadable(reason: Self.damaged)
            }
        }
    }

    public func save(_ config: ProtectedConfig) throws {
        let blob: SecretBuffer
        do { blob = try config.encode() } catch { throw StoreError.writeFailed(reason: "the settings could not be encoded") }
        defer { blob.wipe() }
        // An NSMutableData travels to the Security framework without being copied by the bridge, so
        // zeroing it afterwards clears what wardenrun handed over.
        let data = NSMutableData(length: blob.count) ?? NSMutableData()
        blob.withUnsafeBytes { source in
            if let from = source.baseAddress, source.count > 0 { memcpy(data.mutableBytes, from, source.count) }
        }
        defer { memset_s(data.mutableBytes, data.length, 0, data.length) }

        try withoutInteraction { keychain in
            let access = try makeAccess()
            var attributes = baseQuery(keychain)
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccess as String] = access
            if let keychain { attributes[kSecUseKeychain as String] = keychain }
            attributes[kSecMatchSearchList as String] = nil
            var status = SecItemAdd(attributes as CFDictionary, nil)
            if status == errSecDuplicateItem {
                // Replace the bytes in place, so that at no moment are there two items or none. The
                // access list is NOT part of the update: changing it needs an authorisation that
                // the system asks for with a dialog (found when a test hung on it).
                status = SecItemUpdate(baseQuery(keychain) as CFDictionary,
                                       [kSecValueData as String: data] as CFDictionary)
                if status != errSecSuccess {
                    // The old item cannot be updated by this binary (made by another build): replace it.
                    let removed = SecItemDelete(baseQuery(keychain) as CFDictionary)
                    status = removed == errSecSuccess ? SecItemAdd(attributes as CFDictionary, nil) : removed
                }
            }
            guard status == errSecSuccess else {
                throw StoreError.writeFailed(reason: "the keychain refused the write (status \(status))")
            }
        }
    }

    public func erase() throws {
        try withoutInteraction { keychain in
            let status = SecItemDelete(baseQuery(keychain) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw StoreError.writeFailed(reason: "the keychain refused the delete (status \(status))")
            }
        }
    }

    // MARK: building blocks

    private func baseQuery(_ keychain: SecKeychain?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let keychain { query[kSecMatchSearchList as String] = [keychain] as CFArray }
        return query
    }

    /// An access list with this binary and nobody else.
    private func makeAccess() throws -> SecAccess {
        var application: SecTrustedApplication?
        guard SecTrustedApplicationCreateFromPath(nil, &application) == errSecSuccess, let application else {
            throw StoreError.writeFailed(reason: "this binary could not be named in the access list")
        }
        var access: SecAccess?
        guard SecAccessCreate(service as CFString, [application] as CFArray, &access) == errSecSuccess, let access else {
            throw StoreError.writeFailed(reason: "the access list could not be created")
        }
        return access
    }

    private func openKeychain() throws -> SecKeychain? {
        guard let keychainPath else { return nil }
        var keychain: SecKeychain?
        guard SecKeychainOpen(keychainPath, &keychain) == errSecSuccess, let keychain else {
            throw StoreError.unreadable(reason: "the keychain file cannot be opened")
        }
        return keychain
    }

    /// Runs `body` with user interaction switched off for the whole process and puts the previous
    /// setting back afterwards.
    private func withoutInteraction<T>(_ body: (SecKeychain?) throws -> T) throws -> T {
        Self.interactionLock.lock()
        defer { Self.interactionLock.unlock() }
        var previous: DarwinBoolean = true
        SecKeychainGetUserInteractionAllowed(&previous)
        SecKeychainSetUserInteractionAllowed(false)
        defer { SecKeychainSetUserInteractionAllowed(previous.boolValue) }
        let keychain = try openKeychain()
        duringCall?()
        return try body(keychain)
    }

    private static func readFailure(_ status: OSStatus) -> String {
        switch status {
        case errSecAuthFailed, errSecInteractionNotAllowed, errSecNoAccessForItem, errSecUserCanceled, -25293:
            return notReadable
        default:
            return "the keychain refused the read (status \(status))"
        }
    }

    // MARK: test support

    /// A fresh unlocked keychain file at `path`, for tests only.
    static func createTemporaryKeychain(at path: String) throws {
        let password = temporaryKeychainPassword
        var keychain: SecKeychain?
        let status = SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &keychain)
        guard status == errSecSuccess else { throw StoreError.writeFailed(reason: "cannot create a keychain (status \(status))") }
    }

    static func deleteTemporaryKeychain(at path: String) {
        var keychain: SecKeychain?
        if SecKeychainOpen(path, &keychain) == errSecSuccess, let keychain { SecKeychainDelete(keychain) }
        try? FileManager.default.removeItem(atPath: path)
    }
}
#endif

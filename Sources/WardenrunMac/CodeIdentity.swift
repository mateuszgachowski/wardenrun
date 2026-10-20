#if canImport(Darwin)
import CryptoKit
import Foundation
import Security
import WardenrunCore

/// Who signed a program, as far as the system can tell.
public struct CodeIdentity: Equatable, Sendable {
    public let identifier: String?
    public let teamID: String?
    /// Lower-case hex SHA-1 of the leaf certificate, the way Keychain Access and `codesign` show
    /// it; nil when the code is ad hoc or unsigned.
    public let certificateSHA1: String?
    public let isHardened: Bool
    public let isAdHoc: Bool
    public let designatedRequirement: String?
}

public enum CodeIdentityReader {
    private static let adHocFlag: UInt32 = 0x2
    private static let runtimeFlag: UInt32 = 0x10000

    public static func ofCurrentProcess() -> CodeIdentity? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else { return nil }
        return identity(of: staticCode)
    }

    /// Nil when the file does not exist or carries no signature at all.
    public static func ofFile(_ path: String) -> CodeIdentity? {
        guard let staticCode = staticCode(atPath: path) else { return nil }
        return identity(of: staticCode)
    }

    static func staticCode(atPath path: String) -> SecStaticCode? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &staticCode) == errSecSuccess else {
            return nil
        }
        return staticCode
    }

    private static func identity(of staticCode: SecStaticCode) -> CodeIdentity? {
        var information: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess,
              let info = information as? [String: Any],
              let identifier = info[kSecCodeInfoIdentifier as String] as? String else { return nil }
        let codeFlags = (info[kSecCodeInfoFlags as String] as? UInt32) ?? 0
        let leaf = (info[kSecCodeInfoCertificates as String] as? [SecCertificate])?.first
        var requirementText: String?
        if let requirement = info[kSecCodeInfoDesignatedRequirement as String] {
            var text: CFString?
            if SecRequirementCopyString(requirement as! SecRequirement, SecCSFlags(), &text) == errSecSuccess {
                requirementText = text as String?
            }
        }
        return CodeIdentity(identifier: identifier,
                            teamID: info[kSecCodeInfoTeamIdentifier as String] as? String,
                            certificateSHA1: leaf.map { sha1Hex(SecCertificateCopyData($0) as Data) },
                            isHardened: codeFlags & runtimeFlag != 0,
                            isAdHoc: codeFlags & adHocFlag != 0,
                            designatedRequirement: requirementText)
    }

    private static func sha1Hex(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

/// Accepts a `bw` only if it is Bitwarden's Developer ID signed release: a valid signature that
/// chains to Apple's Developer ID authority, with the given team on the leaf certificate. Ad-hoc,
/// self-signed, Apple-platform and tampered files all fail. The refusal text is fixed and says
/// nothing about why, so that it reveals nothing to a caller who is probing.
public struct SecuritySignatureChecker: BwSignatureChecker {
    public init() {}

    /// The code requirement for "signed by a Developer ID certificate of this team". Nil unless
    /// the team ID is exactly ten upper-case letters and digits, so no other text can reach the
    /// requirement language.
    static func requirementText(teamID: String) -> String? {
        let bytes = Array(teamID.utf8)
        guard bytes.count == 10, bytes.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) }) else { return nil }
        return "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// The process `pid` is code that satisfies the same requirement. `pid` must be our own
    /// unreaped child, so that the number cannot have been reused.
    public func checkRunning(pid: Int32, teamID: String) throws {
        guard let text = Self.requirementText(teamID: teamID) else { throw BwError.signatureMismatch }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let requirement else { throw BwError.signatureMismatch }
        var guest: SecCode?
        let attributes = [kSecGuestAttributePid: Int(pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &guest) == errSecSuccess, let guest else {
            throw BwError.signatureMismatch
        }
        guard SecCodeCheckValidityWithErrors(guest, SecCSFlags(rawValue: kSecCSStrictValidate), requirement, nil) == errSecSuccess else {
            throw BwError.signatureMismatch
        }
    }

    public func check(path: String, teamID: String) throws {
        guard let text = Self.requirementText(teamID: teamID),
              let staticCode = CodeIdentityReader.staticCode(atPath: path) else { throw BwError.signatureMismatch }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let requirement else { throw BwError.signatureMismatch }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        guard SecStaticCodeCheckValidityWithErrors(staticCode, flags, requirement, nil) == errSecSuccess else {
            throw BwError.signatureMismatch
        }
    }
}
#endif

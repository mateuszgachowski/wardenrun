#if canImport(Darwin)
import Darwin
import Foundation
import Security
import WardenrunCore

/// What wardenrun does to itself at startup and what `doctor` reports about it (DESIGN 5.1).
///
/// Together with the hardened-runtime signature these make it hard for another process of the
/// same user to read wardenrun's memory or load code into it. None of it stops the user's own
/// root, and none of it is a substitute for the Touch ID gate.
public enum Hardening {
    private static let ptDenyAttach: CInt = 31
    private static let csRuntime: UInt32 = 0x10000
    private static let sessionHasGraphicAccess: UInt32 = 0x0010

    /// Call first in `main`: refuses debugger attachment and turns core dumps off. A failure is
    /// reported, not ignored. Tests never call this: it would block the runner's debugger.
    public static func apply() -> [CheckResult] {
        let denied = denyAttach()
        let cores = disableCoreDumps()
        return [
            CheckResult(name: "deny-attach", status: denied.ok ? .ok : .fail,
                        detail: denied.ok ? "debuggers cannot attach" : "PT_DENY_ATTACH failed (errno \(denied.errno))"),
            CheckResult(name: "core-dumps", status: cores ? .ok : .fail,
                        detail: cores ? "core dumps are off" : "could not set the core limit to 0"),
        ]
    }

    /// `ptrace` is not exported to Swift; it is looked up in libc.
    private static func denyAttach() -> (ok: Bool, errno: Int32) {
        typealias Ptrace = @convention(c) (CInt, pid_t, UnsafeMutableRawPointer?, CInt) -> CInt
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace") else { return (false, ENOSYS) }
        let result = unsafeBitCast(symbol, to: Ptrace.self)(ptDenyAttach, 0, nil, 0)
        return (result == 0, result == 0 ? 0 : errno)
    }

    /// Soft and hard limit to zero: an unprivileged process cannot raise the hard limit again.
    static func disableCoreDumps() -> Bool {
        var limit = rlimit(rlim_cur: 0, rlim_max: 0)
        return setrlimit(RLIMIT_CORE, &limit) == 0
    }

    /// Names (never values) of the `DYLD_` variables in `environment`, sorted.
    public static func dyldVariables(in environment: [String: String]) -> [String] {
        environment.keys.filter { $0.hasPrefix("DYLD_") }.sorted()
    }

    /// Whether this process runs with the hardened runtime, or nil when it is not signed at all
    /// (or the answer cannot be had).
    public static func hardenedRuntimeEnabled() -> Bool? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let flags = dictionary[kSecCodeInfoFlags as String] as? UInt32 else { return nil }
        return flags & csRuntime != 0
    }

    /// True when this process belongs to a login session with window-server access. Over `ssh` or
    /// from `cron` it is false, and no Touch ID sheet can be shown (DESIGN: no session means deny).
    public static func hasGraphicSession() -> Bool {
        var session: SecuritySessionId = 0
        var attributes: SessionAttributeBits = []
        guard SessionGetInfo(callerSecuritySession, &session, &attributes) == noErr else { return false }
        return attributes.contains(.sessionHasGraphicAccess)
    }

    /// The checks `doctor` prints for this process. The names are stable: the README shows them.
    public static func selfCheck(environment: [String: String]) -> [CheckResult] {
        let dyld = dyldVariables(in: environment)
        var results = [
            dyld.isEmpty
                ? CheckResult(name: "dyld-environment", status: .ok, detail: "no DYLD_ variable is set")
                : CheckResult(name: "dyld-environment", status: .fail,
                              detail: "DYLD_ variables are set (\(dyld.joined(separator: ", "))); wardenrun refuses to run with them"),
        ]
        switch hardenedRuntimeEnabled() {
        case true?:
            results.append(CheckResult(name: "hardened-runtime", status: .ok, detail: "the hardened runtime is on"))
        case false?:
            if CodeIdentityReader.ofCurrentProcess()?.isAdHoc == true {
                // Every SwiftPM build on Apple Silicon is signed ad hoc by the linker, without the runtime.
                results.append(CheckResult(name: "hardened-runtime", status: .warn,
                                           detail: "ad-hoc signature without the hardened runtime (a build from source): other processes could inject code; a release is signed with the runtime"))
            } else {
                results.append(CheckResult(name: "hardened-runtime", status: .fail,
                                           detail: "signed without the hardened runtime: other processes could inject code"))
            }
        case nil:
            results.append(CheckResult(name: "hardened-runtime", status: .warn,
                                       detail: "not signed (a development build); a release build is signed with the hardened runtime"))
        }
        results.append(hasGraphicSession()
            ? CheckResult(name: "graphic-session", status: .ok, detail: "a window-server session is available")
            : CheckResult(name: "graphic-session", status: .fail,
                          detail: "no window-server session (ssh, cron): approvals would be denied"))
        return results
    }
}
#endif

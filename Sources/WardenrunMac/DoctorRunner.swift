#if canImport(Darwin)
import Foundation
import LocalAuthentication
import WardenrunCore

/// Collects the `wardenrun doctor` report (DESIGN 5.8). It looks at this process, at the
/// protected item and at the pinned `bw`; it makes no network call and prints no secret, only
/// counts, booleans and paths that are not secret.
public enum DoctorRunner {
    /// The `bw` release wardenrun's tests ran against; anything else is "untested", not "wrong".
    static let testedBwPrefix = "2026.10."

    public static func run(environment: [String: String], store: SecretStore, paths: WardenrunPaths,
                           signature: BwSignatureChecker = SecuritySignatureChecker(),
                           certificate: () -> CheckResult = certificateCheck,
                           hardening: ([String: String]) -> [CheckResult] = Hardening.selfCheck(environment:),
                           touchID: () -> CheckResult = touchIDCheck) -> DoctorReport {
        var checks = [certificate()]
        checks += hardening(environment)
        let item = DoctorChecks.protectedItem(store: store)
        checks.append(item.check)
        if let config = item.config {
            let pin = DoctorChecks.bwPin(config: config, signature: signature)
            checks.append(pin)
            if pin.status == .ok { checks.append(bwVersionCheck(config: config, paths: paths, signature: signature)) }
        }
        checks.append(DoctorChecks.bwProfile(appDataDirectory: paths.bwAppData))
        checks.append(touchID())
        return DoctorReport(tier: store.tierDescription, checks: checks)
    }

    /// Who signed this binary, as the system sees it. The certificate hash is what the README
    /// publishes for a release build.
    public static func certificateCheck() -> CheckResult {
        guard let identity = CodeIdentityReader.ofCurrentProcess() else {
            return CheckResult(name: "certificate", status: .info, detail: "this binary is not signed")
        }
        var parts = ["identifier \(identity.identifier ?? "?")"]
        if identity.isAdHoc {
            parts.append("ad-hoc signature (a build from source)")
        } else if let team = identity.teamID {
            parts.append("team \(team)")
        }
        if let sha1 = identity.certificateSHA1 { parts.append("certificate SHA-1 \(sha1)") }
        return CheckResult(name: "certificate", status: .info, detail: parts.joined(separator: ", "))
    }

    /// `canEvaluatePolicy` only asks whether the sensor could be used; it never shows a sheet.
    public static func touchIDCheck() -> CheckResult {
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return CheckResult(name: "touch-id", status: .ok, detail: "Touch ID is available")
        }
        switch BiometricApprover.decision(forLAErrorCode: error?.code ?? 0) {
        case .unavailable(let reason): return CheckResult(name: "touch-id", status: .fail, detail: reason)
        default: return CheckResult(name: "touch-id", status: .fail, detail: "Touch ID could not be used")
        }
    }

    private static func isVersionByte(_ byte: UInt8) -> Bool {
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || byte == 0x2E || byte == 0x2D
    }

    /// Runs `bw --version` (the pin was just checked). One short child, no vault, no network.
    private static func bwVersionCheck(config: ProtectedConfig, paths: WardenrunPaths,
                                       signature: BwSignatureChecker) -> CheckResult {
        do {
            let spec = try BwBinaryPolicy.launchSpec(for: config.bwPin, signature: signature)
            let environment = EnvPolicy.bwEnvironment(home: paths.home, appDataDir: paths.bwAppData,
                                                      pinnedDirectories: spec.pinnedDirectories,
                                                      nodeExtraCACerts: config.nodeExtraCACerts, httpsProxy: config.httpsProxy)
            let result = try BwProcess.run(spec: spec, arguments: ["--version", "--nointeraction"],
                                           environment: environment, deadline: 30, captureLimit: 4096)
            guard result.status == .exited(0) else {
                return CheckResult(name: "bw-version", status: .warn, detail: "bw did not report its version")
            }
            let version = String(decoding: result.stdout, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !version.isEmpty, version.utf8.count <= 40,
                  version.utf8.allSatisfy({ Self.isVersionByte($0) }) else {
                return CheckResult(name: "bw-version", status: .warn, detail: "bw reported a version in an unexpected form")
            }
            let tested = version.hasPrefix(testedBwPrefix)
            return CheckResult(name: "bw-version", status: .info,
                               detail: "\(version) (wardenrun is tested with \(testedBwPrefix)x)" + (tested ? "" : "; this one is untested"))
        } catch {
            return CheckResult(name: "bw-version", status: .warn, detail: "bw could not be started to read its version")
        }
    }
}
#endif

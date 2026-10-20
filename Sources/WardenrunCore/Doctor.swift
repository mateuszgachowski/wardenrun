import Foundation

/// One line of `wardenrun doctor`: what was checked, how it came out, and why, in words that
/// never contain a secret or an environment value.
public struct CheckResult: Equatable, Sendable {
    public enum Status: String, Sendable {
        case ok, warn, fail, info
    }

    public let name: String
    public let status: Status
    public let detail: String

    public init(name: String, status: Status, detail: String) {
        self.name = name
        self.status = status
        self.detail = detail
    }
}

/// The output of `wardenrun doctor`: the tier in one honest sentence and one line per check. It
/// is built from `CheckResult`s only, which never contain a secret, and still strips control
/// characters from every detail before printing.
public struct DoctorReport: Sendable {
    public let tier: String
    public let checks: [CheckResult]

    public init(tier: String, checks: [CheckResult]) {
        self.tier = tier
        self.checks = checks
    }

    public func render() -> String {
        var lines = ["wardenrun doctor", "tier: " + Self.oneLine(tier)]
        for check in checks {
            let label: String
            switch check.status {
            case .ok: label = "ok   "
            case .warn: label = "warn "
            case .fail: label = "FAIL "
            case .info: label = "info "
            }
            lines.append(label + " " + Self.oneLine(check.name) + "  " + Self.oneLine(check.detail))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// 0 when nothing failed; a warning does not fail doctor.
    public var exitCode: Int32 { checks.contains { $0.status == .fail } ? 1 : 0 }

    private static func oneLine(_ text: String) -> String {
        var output = ""
        for scalar in text.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .lineSeparator, .paragraphSeparator:
                if scalar.value == 0x0A || scalar.value == 0x0D || scalar.value == 0x09 { output += " " }
            case .format:
                break
            default:
                output.unicodeScalars.append(scalar)
            }
        }
        return output
    }
}

/// The doctor checks that need only the core: they ask the store and the pin policy, and they
/// report counts, booleans and paths that are not secret.
public enum DoctorChecks {
    public static func protectedItem(store: SecretStore) -> (check: CheckResult, config: ProtectedConfig?) {
        do {
            guard let config = try store.load() else {
                return (CheckResult(name: "protected-item", status: .info,
                                    detail: "no protected item yet; run `wardenrun setup`"), nil)
            }
            let collections = config.collectionIDs.count
            return (CheckResult(name: "protected-item", status: .ok,
                                detail: "readable: 1 organization, \(collections) collection\(collections == 1 ? "" : "s")"), config)
        } catch let error as StoreError {
            switch error {
            case .unreadable(let reason), .writeFailed(let reason):
                return (CheckResult(name: "protected-item", status: .fail, detail: reason), nil)
            }
        } catch {
            return (CheckResult(name: "protected-item", status: .fail, detail: "the protected item could not be read"), nil)
        }
    }

    /// Runs the same pin policy as every `run`, so doctor says what `run` would say.
    public static func bwPin(config: ProtectedConfig, signature: BwSignatureChecker) -> CheckResult {
        do {
            let spec = try BwBinaryPolicy.launchSpec(for: config.bwPin, signature: signature)
            switch config.bwPin {
            case .signedRelease(let teamID, _):
                return CheckResult(name: "bw-pin", status: .ok,
                                   detail: "signed release of team \(teamID) at \(spec.executable)")
            }
        } catch BwError.signatureMismatch {
            if case .signedRelease(let teamID, _) = config.bwPin {
                return CheckResult(name: "bw-pin", status: .fail,
                                   detail: "the pinned bw is not usable: its code signature does not match team \(teamID)")
            }
            return CheckResult(name: "bw-pin", status: .fail, detail: "the pinned bw is not usable")
        } catch BwError.binaryNotAllowed(let reason) {
            return CheckResult(name: "bw-pin", status: .fail, detail: "the pinned bw is not usable: \(reason)")
        } catch {
            return CheckResult(name: "bw-pin", status: .fail, detail: "the pinned bw is not usable")
        }
    }

    /// Whether `bw` has a profile of its own for wardenrun. Local only: a file check, no `bw` run.
    public static func bwProfile(appDataDirectory: String) -> CheckResult {
        if FileManager.default.fileExists(atPath: appDataDirectory + "/data.json") {
            return CheckResult(name: "bw-profile", status: .ok, detail: "bw has a profile of its own for wardenrun")
        }
        return CheckResult(name: "bw-profile", status: .info, detail: "no bw profile yet; `wardenrun setup` creates it")
    }
}

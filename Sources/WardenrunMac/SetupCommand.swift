#if canImport(Darwin)
import Darwin
import Foundation
import WardenrunCore

/// `wardenrun setup` on a Mac: plugs the terminal, Touch ID, the keychain item and `bw` into
/// `SetupFlow`, and turns every outcome into one line and an exit code. All decisions live in
/// `SetupFlow`; this file only connects things.
public enum SetupCommand {
    /// Bitwarden Inc's Developer ID team, the only signer of `bw` that wardenrun accepts.
    public static let bitwardenTeamID = "LTZ2PFU5D6"

    /// 0 done, 1 failed, 64 not a terminal, 77 not approved.
    public static func run(options: SetupOptions, environment: [String: String], paths: WardenrunPaths,
                           store: SecretStore, approver: Approver = BiometricApprover(),
                           signature: BwSignatureChecker = SecuritySignatureChecker(),
                           output: (String) -> Void, errorOutput: @escaping @Sendable (String) -> Void) -> Int32 {
        let gate = ApprovalGate(stateDirectory: paths.stateDirectory)
        let plannedPin = BwPin.signedRelease(teamID: bitwardenTeamID, path: paths.installedBw)
        let audit = AuditLog(path: paths.auditLog, redactor: { $0 })

        let steps = SetupSteps(
            isInteractive: Terminal.isInteractive(),
            plannedPin: plannedPin,
            ask: { question, fallback in
                let label = [
                    "server": "Vaultwarden address (https://...)",
                    "email": "Account e-mail",
                    "organization": "Organization id",
                    "collections": "Collection ids (comma-separated)",
                ][question] ?? question
                let shown = fallback.map { "\(label) [\($0)]: " } ?? "\(label): "
                FileHandle.standardError.write(Data(shown.utf8))
                guard let line = readLine() else { throw SetupError.cancelled }
                return line
            },
            readPassword: {
                do {
                    return try Terminal.readHidden(prompt: "Master password (hidden, not stored anywhere else): ")
                } catch TerminalError.notInteractive {
                    throw SetupError.notInteractive
                } catch TerminalError.tooLong {
                    throw SetupError.invalid(field: "password")
                } catch {
                    throw SetupError.cancelled
                }
            },
            existing: { try store.load() },
            approve: { text in
                try gate.guarded { approver.approve(reason: text, timeout: 60) }
            },
            install: {
                guard let source = options.bwPath ?? findBw(in: environment["PATH"] ?? "") else {
                    throw SetupError.installFailed(reason: "bw was not found; install the official bw release and pass --bw PATH")
                }
                return try Setup.installBw(from: source, teamID: bitwardenTeamID, to: paths.installedBw, signature: signature)
            },
            configureBw: { config in
                try Setup.configureBw(config: config, appDataDir: paths.bwAppData, home: paths.home,
                                      lockPath: paths.lockFile, signature: signature, timeouts: .default)
            },
            verify: { config in
                let vault = BwVault(config: config, appDataDir: paths.bwAppData, home: paths.home,
                                    lockPath: paths.lockFile, signature: signature)
                try Setup.verify(vault: vault)
            },
            save: { config in try store.save(config) },
            audit: { event in
                var event = event
                event.tier = store.tierDescription
                do { try audit.append(event) } catch { errorOutput("wardenrun: setup is saved, but the audit log could not be written") }
            })

        do {
            output(try SetupFlow.run(steps))
            return 0
        } catch let error as SetupError {
            errorOutput("wardenrun: " + error.message)
            switch error {
            case .notInteractive: return 64
            case .denied: return 77
            default: return 1
            }
        } catch let refusal as GateRefusal {
            errorOutput("wardenrun: " + refusal.message)
            return 77
        } catch let error as StoreError {
            switch error {
            case .unreadable(let reason), .writeFailed(let reason):
                errorOutput("wardenrun: the protected item could not be saved or read (\(reason))")
            }
            return 1
        } catch {
            errorOutput("wardenrun: setup failed")
            return 1
        }
    }

    /// The first executable file called `bw` along `path`. The result is only a file to copy
    /// from: `Setup.installBw` checks the copy's signature, so a fake `bw` on `PATH` is refused.
    static func findBw(in path: String) -> String? {
        for directory in path.split(separator: ":") where directory.hasPrefix("/") {
            let candidate = String(directory) + "/bw"
            if access(candidate, X_OK) == 0 { return candidate }
        }
        return nil
    }
}
#endif

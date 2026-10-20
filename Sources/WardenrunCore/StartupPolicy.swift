import Foundation

/// When wardenrun refuses to start a command that touches secrets (`setup`, `run`, `new`),
/// decided from the self-check results alone so that the rule is testable everywhere.
public enum StartupPolicy {
    /// The sentence to print before exiting 78, or nil when it is safe to go on.
    ///
    /// - Any failed check refuses: debugger attach not denied, core dumps not off, a `DYLD_*`
    ///   variable present, a signed binary without the hardened runtime, no window-server session.
    /// - A binary that is not hardened but only warns (an ad-hoc or unsigned build from source) is
    ///   refused too, unless `allowUnhardened`, which only a debug build passes: a switch in the
    ///   environment would be a switch the agent can flip.
    public static func refusal(checks: [CheckResult], allowUnhardened: Bool) -> String? {
        if let failure = checks.first(where: { $0.status == .fail }) {
            return "refusing to run: \(failure.name): \(failure.detail)"
        }
        if !allowUnhardened {
            guard let runtime = checks.first(where: { $0.name == "hardened-runtime" }) else {
                return "refusing to run: no hardened-runtime check was made"
            }
            if runtime.status != .ok { return "refusing to run: \(runtime.name): \(runtime.detail)" }
        }
        return nil
    }
}

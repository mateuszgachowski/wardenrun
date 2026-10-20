import Foundation

/// Which ancestor the sheet names as the one that asked (DESIGN 5.3). A shell between the agent
/// and wardenrun says nothing, so the nearest parent that is not a shell is chosen; when every
/// parent is a shell, the nearest one.
public enum ParentDescription {
    static let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "login", "env", "sudo"]

    /// `chain` holds short process names, nearest first.
    public static func pick(_ chain: [String]) -> String? {
        chain.first { !shells.contains($0) } ?? chain.first
    }
}

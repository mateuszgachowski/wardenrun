import Foundation

/// Everything `wardenrun setup` does that touches the outside world, as closures, so that the
/// order of the steps is one tested function (`SetupFlow.run`) and `main.swift` only plugs in
/// the terminal, Touch ID, the keychain and `bw`.
public struct SetupSteps: Sendable {
    public var isInteractive: Bool
    /// The pin the config will carry: the copy of `bw` that `install` is going to make.
    public var plannedPin: BwPin
    /// A visible question; the second argument is the old value, offered as the default.
    public var ask: @Sendable (_ question: String, _ fallback: String?) throws -> String
    public var readPassword: @Sendable () throws -> SecretBuffer
    /// The item that is stored now. `StoreError` from it means "treat as nothing stored".
    public var existing: @Sendable () throws -> ProtectedConfig?
    public var approve: @Sendable (_ text: String) throws -> ApprovalDecision
    public var install: @Sendable () throws -> BwPin
    public var configureBw: @Sendable (ProtectedConfig) throws -> Void
    public var verify: @Sendable (ProtectedConfig) throws -> Void
    /// Puts the staged `bw` profile (logged in and verified) in place of the live one.
    public var commitProfile: @Sendable () throws -> Void
    /// Removes whatever `configureBw` staged and `commitProfile` did not take. Called on every way out.
    public var discardProfile: @Sendable () -> Void
    public var save: @Sendable (ProtectedConfig) throws -> Void
    public var audit: @Sendable (AuditEvent) -> Void

    public init(isInteractive: Bool, plannedPin: BwPin,
                ask: @escaping @Sendable (String, String?) throws -> String,
                readPassword: @escaping @Sendable () throws -> SecretBuffer,
                existing: @escaping @Sendable () throws -> ProtectedConfig?,
                approve: @escaping @Sendable (String) throws -> ApprovalDecision,
                install: @escaping @Sendable () throws -> BwPin,
                configureBw: @escaping @Sendable (ProtectedConfig) throws -> Void,
                verify: @escaping @Sendable (ProtectedConfig) throws -> Void,
                commitProfile: @escaping @Sendable () throws -> Void,
                discardProfile: @escaping @Sendable () -> Void,
                save: @escaping @Sendable (ProtectedConfig) throws -> Void,
                audit: @escaping @Sendable (AuditEvent) -> Void) {
        self.isInteractive = isInteractive
        self.plannedPin = plannedPin
        self.ask = ask
        self.readPassword = readPassword
        self.existing = existing
        self.approve = approve
        self.install = install
        self.configureBw = configureBw
        self.verify = verify
        self.commitProfile = commitProfile
        self.discardProfile = discardProfile
        self.save = save
        self.audit = audit
    }
}

public enum SetupFlow {
    /// Nothing is changed before a human approved the new values. `bw` is logged in under a
    /// staged profile; the live profile is replaced and the protected item saved only after
    /// unlock/lock worked with exactly those values, so a failure leaves the working setup as it
    /// was. Returns the one line to print.
    public static func run(_ steps: SetupSteps) throws -> String {
        try Setup.requireInteractive(steps.isInteractive)

        let old: ProtectedConfig?
        var replacesUnreadable = false
        do { old = try steps.existing() } catch is StoreError { old = nil; replacesUnreadable = true }

        func answer(_ question: String, _ fallback: String?) throws -> String {
            let typed = try steps.ask(question, fallback).trimmingCharacters(in: .whitespacesAndNewlines)
            return typed.isEmpty ? (fallback ?? "") : typed
        }
        let server = try answer("server", old?.serverURL.absoluteString)
        let email = try answer("email", old?.accountEmail)
        let organization = try answer("organization", old?.organizationID)
        let collections = try answer("collections", old?.collectionIDs.joined(separator: ", "))
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let password = try steps.readPassword()

        let config = try Setup.makeConfig(SetupInput(
            serverURL: server, email: email, organizationID: organization, collectionIDs: collections,
            masterPassword: password, bwPin: steps.plannedPin,
            nodeExtraCACerts: old?.nodeExtraCACerts, httpsProxy: old?.httpsProxy))

        let text = try Setup.approvalText(old: old, new: config, replacesUnreadable: replacesUnreadable)
        switch try steps.approve(text) {
        case .approved: break
        case .unavailable(let reason): throw SetupError.approvalUnavailable(reason: reason)
        case .denied, .timedOut: throw SetupError.denied
        }

        defer { steps.discardProfile() }
        guard try steps.install() == steps.plannedPin else {
            throw SetupError.installFailed(reason: "the installed bw is not the one that was approved")
        }
        try steps.configureBw(config)
        try steps.verify(config)
        try steps.commitProfile()
        try steps.save(config)
        steps.audit(AuditEvent(event: .setup))

        let count = config.collectionIDs.count
        return "setup done: \(config.serverURL.host ?? server), \(count) collection\(count == 1 ? "" : "s"); check with `wardenrun doctor`"
    }
}

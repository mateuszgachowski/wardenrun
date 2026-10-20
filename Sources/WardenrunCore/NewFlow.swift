import Foundation

/// Everything `wardenrun new` does that touches the outside world (DESIGN 5.6).
public struct NewSteps: Sendable {
    public var context: @Sendable () -> (cwd: String, parentChain: [String])
    public var loadConfig: @Sendable () throws -> ProtectedConfig?
    public var approve: @Sendable (_ text: String) throws -> ApprovalDecision
    public var generate: @Sendable (_ length: Int, _ charset: PasswordCharset) throws -> SecretBuffer
    /// Creates the item in the first allowed collection and returns its id.
    public var create: @Sendable (_ config: ProtectedConfig, _ options: NewOptions, _ password: SecretBuffer) throws -> String
    public var audit: @Sendable (AuditEvent) -> Void
    public var warn: @Sendable (String) -> Void

    public init(context: @escaping @Sendable () -> (cwd: String, parentChain: [String]),
                loadConfig: @escaping @Sendable () throws -> ProtectedConfig?,
                approve: @escaping @Sendable (String) throws -> ApprovalDecision,
                generate: @escaping @Sendable (Int, PasswordCharset) throws -> SecretBuffer,
                create: @escaping @Sendable (ProtectedConfig, NewOptions, SecretBuffer) throws -> String,
                audit: @escaping @Sendable (AuditEvent) -> Void,
                warn: @escaping @Sendable (String) -> Void) {
        self.context = context
        self.loadConfig = loadConfig
        self.approve = approve
        self.generate = generate
        self.create = create
        self.audit = audit
        self.warn = warn
    }
}

public enum NewFlow {
    /// Ask first, then make the password, store it, wipe it. The password is never returned,
    /// printed or logged; the one output line names the item, its id and the collection.
    public static func run(_ options: NewOptions, _ steps: NewSteps) -> (code: Int32, line: String?) {
        let context = steps.context()
        func event(_ kind: AuditEventKind) -> AuditEvent {
            AuditEvent(event: kind, item: options.name, cwd: context.cwd, parentChain: context.parentChain)
        }

        let config: ProtectedConfig
        do {
            guard let loaded = try steps.loadConfig() else {
                steps.warn("wardenrun is not set up; run `wardenrun setup` first")
                return (RunExit.failed, nil)
            }
            config = loaded
        } catch StoreError.unreadable(let reason), StoreError.writeFailed(let reason) {
            steps.warn("the protected item cannot be read (\(TextEscaping.escape(reason))); run `wardenrun doctor`")
            return (RunExit.failed, nil)
        } catch {
            steps.warn("the protected item cannot be read; run `wardenrun doctor`")
            return (RunExit.failed, nil)
        }
        defer { config.masterPassword.wipe() }
        let collection = config.collectionIDs[0]

        let text: String
        do {
            text = try approvalText(options, collection: collection, parent: context.parentChain.first)
        } catch let error as ApprovalTextError {
            if case .tooLong(let count) = error {
                steps.warn("the request is too long to review (\(count) > \(ApprovalTextBuilder.budget)); use a shorter name")
            }
            steps.audit(event(.denied))
            return (RunExit.notApproved, nil)
        } catch {
            steps.warn("the approval text could not be built")
            steps.audit(event(.error))
            return (RunExit.notApproved, nil)
        }

        let decision: ApprovalDecision
        do {
            decision = try steps.approve(text)
        } catch let refusal as GateRefusal {
            steps.warn(refusal.message)
            steps.audit(event(.error))
            return (RunExit.notApproved, nil)
        } catch {
            steps.warn("the approval could not be asked for")
            steps.audit(event(.error))
            return (RunExit.notApproved, nil)
        }
        switch decision {
        case .approved: break
        case .denied:
            steps.warn("the request was not approved")
            steps.audit(event(.denied))
            return (RunExit.notApproved, nil)
        case .timedOut:
            steps.warn("the approval timed out")
            steps.audit(event(.timeout))
            return (RunExit.notApproved, nil)
        case .unavailable(let reason):
            steps.warn("no approval was possible: \(TextEscaping.escape(reason))")
            steps.audit(event(.error))
            return (RunExit.notApproved, nil)
        }

        let password: SecretBuffer
        do {
            password = try steps.generate(options.length, options.charset)
        } catch {
            steps.warn((error as? PasswordError)?.message ?? "the password could not be generated")
            steps.audit(event(.error))
            return (RunExit.failed, nil)
        }
        defer { password.wipe() }

        let id: String
        do {
            id = try steps.create(config, options, password)
        } catch {
            steps.warn(RunFlow.describe(error))
            steps.audit(event(.error))
            return (RunExit.failed, nil)
        }
        steps.audit(event(.new))
        let name = TextEscaping.escape(options.name, quoting: true)
        return (0, "created \"\(name)\" (id \(TextEscaping.escape(id))) in \(TextEscaping.escape(collection))")
    }

    /// `create item "<name>" in collection <id>; [username …;] [uri …;] [stored as env:X;]
    /// password of N characters (…), never shown (from <parent>) [end]`, escaped, at most 400 units.
    static func approvalText(_ options: NewOptions, collection: String, parent: String?) throws -> String {
        func quoted(_ value: String) -> String { "\"" + TextEscaping.escape(value, quoting: true) + "\"" }
        var parts = ["create item \(quoted(options.name)) in collection \(TextEscaping.escape(collection))"]
        if let username = options.username { parts.append("username \(quoted(username))") }
        if let uri = options.uri { parts.append("uri \(quoted(uri))") }
        if let env = options.env { parts.append("stored as env:\(TextEscaping.escape(env))") }
        let kind = options.charset == .alnum ? "letters and digits" : "letters, digits and symbols"
        parts.append("password of \(options.length) characters (\(kind)), never shown")
        var result = parts.joined(separator: "; ")
        if let parent { result += " (from \(TextEscaping.escape(parent)))" }
        result += " [end]"
        let count = result.utf16.count
        guard count <= ApprovalTextBuilder.budget else { throw ApprovalTextError.tooLong(count) }
        return result
    }
}

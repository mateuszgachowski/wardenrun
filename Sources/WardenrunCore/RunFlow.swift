import Foundation

/// What `RunFlow` needs to know about the caller, read once.
public struct RunContext: Sendable {
    public var cwd: String
    /// Short names of the parent processes, nearest first.
    public var parentChain: [String]
    public var callerEnvironment: [String: String]
    /// Whether the current user can write the file at that path (it could be swapped before it starts).
    public var executableIsWritable: @Sendable (String) -> Bool

    public init(cwd: String, parentChain: [String], callerEnvironment: [String: String],
                executableIsWritable: @escaping @Sendable (String) -> Bool) {
        self.cwd = cwd
        self.parentChain = parentChain
        self.callerEnvironment = callerEnvironment
        self.executableIsWritable = executableIsWritable
    }
}

/// Everything `wardenrun run` does that touches the outside world, as closures, so that the order
/// of the steps is one tested function and `main.swift` only plugs in the keychain, Touch ID,
/// `bw` and the process.
public struct RunSteps: Sendable {
    public var resolve: @Sendable (RunOptions) throws -> ResolvedExecutable
    public var context: @Sendable () -> RunContext
    public var loadConfig: @Sendable () throws -> ProtectedConfig?
    /// The program hash recorded by the last approval of this item and executable, if any.
    public var previousHash: @Sendable (_ item: String, _ executable: String) -> String?
    /// The gate and the sheet. Throws `GateRefusal` when nothing was asked.
    public var approve: @Sendable (_ text: String) throws -> ApprovalDecision
    public var fetch: @Sendable (_ config: ProtectedConfig, _ itemName: String) throws -> BwFetchedItem
    public var makeSecretFiles: @Sendable () -> SecretFiles
    /// `ExecResolver.stillMatches` in production: the file is still the one that was approved.
    public var stillMatches: @Sendable (ResolvedExecutable) -> Bool
    public var spawn: @Sendable (_ executable: ResolvedExecutable, _ environment: [String: String],
                                 _ secretEnvironment: [String: SecretBuffer], _ stdin: StdinSource,
                                 _ needles: [Needle]) throws -> ChildResult
    public var audit: @Sendable (AuditEvent) -> Void
    /// One sentence for the person (and the agent) at the terminal; the caller adds the prefix.
    public var warn: @Sendable (String) -> Void

    public init(resolve: @escaping @Sendable (RunOptions) throws -> ResolvedExecutable,
                context: @escaping @Sendable () -> RunContext,
                loadConfig: @escaping @Sendable () throws -> ProtectedConfig?,
                previousHash: @escaping @Sendable (String, String) -> String?,
                approve: @escaping @Sendable (String) throws -> ApprovalDecision,
                fetch: @escaping @Sendable (ProtectedConfig, String) throws -> BwFetchedItem,
                makeSecretFiles: @escaping @Sendable () -> SecretFiles,
                stillMatches: @escaping @Sendable (ResolvedExecutable) -> Bool,
                spawn: @escaping @Sendable (ResolvedExecutable, [String: String], [String: SecretBuffer], StdinSource, [Needle]) throws -> ChildResult,
                audit: @escaping @Sendable (AuditEvent) -> Void,
                warn: @escaping @Sendable (String) -> Void) {
        self.resolve = resolve
        self.context = context
        self.loadConfig = loadConfig
        self.previousHash = previousHash
        self.approve = approve
        self.fetch = fetch
        self.makeSecretFiles = makeSecretFiles
        self.stillMatches = stillMatches
        self.spawn = spawn
        self.audit = audit
        self.warn = warn
    }
}

/// Exit codes of `wardenrun run`. The child's own code is passed through unchanged; these are the
/// ones wardenrun itself produces.
public enum RunExit {
    public static let failed: Int32 = 1
    public static let usage: Int32 = 64
    public static let notApproved: Int32 = 77
    /// What a shell says for "found, but cannot be run" and "not found".
    public static let notExecutable: Int32 = 126
    public static let notFound: Int32 = 127
}

public enum RunFlow {
    /// Resolve, ask, fetch, inject, start, relay, clean up (DESIGN 5.1, 5.4). Nothing is fetched
    /// before a human approved, and the vault item is wiped before the command starts.
    public static func run(_ options: RunOptions, _ steps: RunSteps) -> Int32 {
        let executable: ResolvedExecutable
        do {
            executable = try steps.resolve(options)
        } catch let error as ExecError {
            return refuseResolve(error, steps)
        } catch {
            steps.warn("the command could not be resolved")
            return RunExit.failed
        }
        let context = steps.context()
        func event(_ kind: AuditEventKind) -> AuditEvent {
            AuditEvent(event: kind, item: options.item, commandLine: executable.argv, executable: executable.path,
                       executableSHA256: executable.sha256, cwd: context.cwd, parentChain: context.parentChain)
        }

        // The protected item is read before anything is asked: no setup means no question.
        let config: ProtectedConfig
        do {
            guard let loaded = try steps.loadConfig() else {
                steps.warn("wardenrun is not set up; run `wardenrun setup` first")
                return RunExit.failed
            }
            config = loaded
        } catch StoreError.unreadable(let reason), StoreError.writeFailed(let reason) {
            steps.warn("the protected item cannot be read (\(TextEscaping.escape(reason))); run `wardenrun doctor`")
            return RunExit.failed
        } catch {
            steps.warn("the protected item cannot be read; run `wardenrun doctor`")
            return RunExit.failed
        }
        defer { config.masterPassword.wipe() }

        // The question.
        let request = ApprovalRequest(item: options.item, executable: executable, parent: context.parentChain.first,
                                      callerEnvironment: context.callerEnvironment,
                                      executableIsWritable: context.executableIsWritable(executable.path),
                                      previousHash: steps.previousHash(options.item, executable.path))
        let text: String
        do {
            text = try ApprovalTextBuilder.text(for: request)
        } catch let error as ApprovalTextError {
            steps.warn(error.message)
            steps.audit(event(.denied))
            return RunExit.notApproved
        } catch {
            steps.warn("the approval text could not be built")
            steps.audit(event(.error))
            return RunExit.notApproved
        }
        let decision: ApprovalDecision
        do {
            decision = try steps.approve(text)
        } catch let refusal as GateRefusal {
            steps.warn(refusal.message)
            steps.audit(event(.error))
            return RunExit.notApproved
        } catch {
            steps.warn("the approval could not be asked for")
            steps.audit(event(.error))
            return RunExit.notApproved
        }
        switch decision {
        case .approved:
            break
        case .denied:
            steps.warn("the request was not approved")
            steps.audit(event(.denied))
            return RunExit.notApproved
        case .timedOut:
            steps.warn("the approval timed out")
            steps.audit(event(.timeout))
            return RunExit.notApproved
        case .unavailable(let reason):
            steps.warn("no approval was possible: \(TextEscaping.escape(reason))")
            steps.audit(event(.error))
            return RunExit.notApproved
        }
        steps.audit(event(.approved))

        // The secret.
        func fail(_ error: Error) -> Int32 {
            steps.warn(describe(error))
            steps.audit(event(.error))
            return RunExit.failed
        }
        let item: BwFetchedItem
        do {
            item = try steps.fetch(config, options.item)
        } catch {
            config.masterPassword.wipe()
            return fail(error)
        }
        config.masterPassword.wipe()
        defer { item.wipe() }

        let plan: InjectionPlan
        do {
            plan = try InjectionPlan.make(options: options, item: item)
        } catch {
            return fail(error)
        }
        defer { plan.wipe() }
        item.wipe()

        let masks = MaskNeedles.plan(for: plan.maskSecrets)
        if !masks.tooShort.isEmpty {
            steps.warn("an injected value is shorter than \(MaskNeedles.minimumLength) characters and will not be hidden if the command prints it")
        }

        var plainEnvironment = context.callerEnvironment
        let secretFiles: SecretFiles? = plan.files.isEmpty ? nil : steps.makeSecretFiles()
        defer { secretFiles?.removeAll() }
        if let secretFiles {
            do {
                let paths = try secretFiles.write(plan.files)
                plainEnvironment = try EnvPolicy.childEnvironment(caller: plainEnvironment, injected: paths)
            } catch let error as RunError {
                return fail(error)
            } catch {
                return fail(RunError.tempFile)
            }
        }

        // Last look at the program, then go.
        guard steps.stillMatches(executable) else {
            steps.warn("the program changed after it was approved; nothing was started")
            steps.audit(event(.error))
            return RunExit.failed
        }
        let stdin: StdinSource = plan.stdin.map { .data($0) } ?? .inherit
        let result: ChildResult
        do {
            result = try steps.spawn(executable, plainEnvironment, plan.environment, stdin, masks.needles)
        } catch let error as ChildError {
            steps.warn(describe(error))
            steps.audit(event(.error))
            if case .spawnFailed(let code) = error, code == ENOENT { return RunExit.notFound }
            return RunExit.notExecutable
        } catch {
            return fail(error)
        }
        steps.audit(AuditEvent(event: .finished, item: options.item, executable: executable.path,
                               exitStatus: result.exitCode, durationMs: Int((result.duration * 1000).rounded())))
        return result.exitCode
    }

    // MARK: messages

    private static func refuseResolve(_ error: ExecError, _ steps: RunSteps) -> Int32 {
        switch error {
        case .emptyCommand:
            steps.warn("no command given")
            return RunExit.usage
        case .notFound(let name):
            steps.warn("command not found: \(TextEscaping.escape(name))")
            return RunExit.notFound
        case .notExecutable(let name):
            steps.warn("not executable: \(TextEscaping.escape(name))")
            return RunExit.notExecutable
        case .notRegularFile(let name):
            steps.warn("not a regular file: \(TextEscaping.escape(name))")
            return RunExit.notExecutable
        case .nulInArgument(let index):
            steps.warn("argument \(index) contains a NUL byte")
            return RunExit.usage
        }
    }

    /// A fixed sentence for a failure after the approval. Never a byte of a value.
    static func describe(_ error: Error) -> String {
        switch error {
        case let error as RunError:
            return error.message
        case BwError.unsupportedField(let field):
            let name = TextEscaping.escape(field, quoting: true)
            return field == "totp" ? "the field \"\(name)\" is not supported yet (it would hand out the stored seed)"
                                   : "the field \"\(name)\" is not supported"
        case let error as BwError:
            return "could not get the secret: \(error.summary)"
        case let error as ChildError:
            switch error {
            case .spawnFailed(let code): return "the command could not be started (error \(code))"
            case .pipeFailed(let code): return "the command could not be started: no pipe (error \(code))"
            }
        case is EnvPolicyError:
            return "an environment variable name is not allowed"
        default:
            return "the run failed"
        }
    }
}

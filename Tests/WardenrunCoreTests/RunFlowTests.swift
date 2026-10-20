import Foundation
import Testing
@testable import WardenrunCore

/// Every step of a run as a fake that writes into one trace.
private final class Rig: @unchecked Sendable {
    private let lock = NSLock()
    private var _trace: [String] = []
    private var _audits: [AuditEvent] = []
    private var _warnings: [String] = []

    var trace: [String] { lock.lock(); defer { lock.unlock() }; return _trace }
    var audits: [AuditEvent] { lock.lock(); defer { lock.unlock() }; return _audits }
    var warnings: [String] { lock.lock(); defer { lock.unlock() }; return _warnings }
    func note(_ text: String) { lock.lock(); _trace.append(text); lock.unlock() }

    // knobs
    var options = RunOptions(item: "it-github", env: [], files: [], stdin: nil, command: ["tool", "--flag", "arg"])
    var executable = ResolvedExecutable.sample
    var resolveError: Error?
    var configured = true
    var configError: Error?
    var password = SecretBuffer(copying: Array("master-password-VALUE".utf8))
    var decision: ApprovalDecision = .approved
    var approveError: Error?
    var itemJSON = #"{"login":{"password":"P4SSWORD-VALUE"},"fields":[{"name":"env:API_TOKEN","value":"TOKEN-VALUE-1"}]}"#
    var fetchError: Error?
    var stillMatches = true
    var spawnError: Error?
    var childResult = ChildResult(end: .exited(0), exitCode: 0, duration: 1.5)
    var previousHash: String?
    var writable = false
    var parentChain = ["zsh", "Terminal"]
    var callerEnvironment = ["PATH": "/usr/bin", "HOME": "/Users/x"]
    var secretFilesParent = ""

    // observations
    private(set) var approvedText: String?
    private(set) var fetchedItem: BwFetchedItem?
    private(set) var itemWipedAtSpawn: Bool?
    private(set) var configPasswordWipedAtSpawn: Bool?
    private(set) var spawnedEnvironment: [String: String]?
    private(set) var spawnedSecretEnvironment: [String: String]?
    private(set) var spawnedStdin: String?
    private(set) var spawnedHadStdinData = false
    private(set) var spawnedNeedleCount = 0
    private(set) var fileContentsAtSpawn: [String: String] = [:]
    private(set) var fileModeAtSpawn: Int?
    private(set) var entriesWhenFinishedWasWritten: [String]?

    func steps() -> RunSteps {
        RunSteps(
            resolve: { [self] _ in
                note("resolve")
                if let resolveError { throw resolveError }
                return executable
            },
            context: { [self] in
                note("context")
                return RunContext(cwd: "/work", parentChain: parentChain, callerEnvironment: callerEnvironment,
                                  executableIsWritable: { [self] _ in writable })
            },
            loadConfig: { [self] in
                note("loadConfig")
                if let configError { throw configError }
                guard configured else { return nil }
                return try ProtectedConfig(serverURL: URL(string: "https://vault.example")!, accountEmail: "a@b.example",
                                           organizationID: "org-1", collectionIDs: ["col-1"], masterPassword: password,
                                           bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/bw"))
            },
            previousHash: { [self] _, _ in note("previousHash"); return previousHash },
            approve: { [self] text in
                note("approve")
                approvedText = text
                if let approveError { throw approveError }
                return decision
            },
            fetch: { [self] _, _ in
                note("fetch")
                if let fetchError { throw fetchError }
                let item = BwFetchedItem(itemJSON: SecretBuffer(copying: Array(itemJSON.utf8)), id: "item-1", name: "it-github")
                fetchedItem = item
                return item
            },
            makeSecretFiles: { [self] in note("makeSecretFiles"); return SecretFiles(parent: secretFilesParent) },
            stillMatches: { [self] _ in note("stillMatches"); return stillMatches },
            spawn: { [self] exe, environment, secretEnvironment, stdin, needles in
                note("spawn")
                itemWipedAtSpawn = fetchedItem?.isWipedForTesting
                configPasswordWipedAtSpawn = password.isWiped
                spawnedEnvironment = environment
                spawnedSecretEnvironment = secretEnvironment.mapValues { $0.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }
                if case .data(let buffer) = stdin {
                    spawnedHadStdinData = true
                    spawnedStdin = buffer.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
                }
                spawnedNeedleCount = needles.count
                for (name, value) in environment where value.hasPrefix(secretFilesParent) {
                    fileContentsAtSpawn[name] = try? String(contentsOfFile: value, encoding: .utf8)
                    fileModeAtSpawn = permissionBits(of: value)
                }
                if let spawnError { throw spawnError }
                return childResult
            },
            audit: { [self] event in
                lock.lock(); _audits.append(event); lock.unlock()
                note("audit:\(event.event.rawValue)")
                if event.event == .finished {
                    entriesWhenFinishedWasWritten = (try? FileManager.default.contentsOfDirectory(atPath: secretFilesParent)) ?? ["unreadable"]
                }
            },
            warn: { [self] text in lock.lock(); _warnings.append(text); lock.unlock(); note("warn") })
    }
}

private extension ResolvedExecutable {
    static let sample = ResolvedExecutable(path: "/usr/local/bin/tool", argv: ["tool", "--flag", "arg"], sha256: String(repeating: "ab", count: 32))
}

struct RunFlowTests {
    private func withRig(_ body: (Rig) throws -> Void) throws {
        try withTempDirectory { parent in
            try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true)
            let rig = Rig()
            rig.secretFilesParent = parent
            try body(rig)
        }
    }

    @Test func theStepsRunInTheDocumentedOrder() throws {
        try withRig { rig in
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 0)
            #expect(rig.trace == ["resolve", "context", "loadConfig", "previousHash", "approve", "audit:approved",
                                  "fetch", "stillMatches", "spawn", "audit:finished"])
        }
    }

    @Test func notSetUpAsksNothing() throws {
        try withRig { rig in
            rig.configured = false
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(rig.trace == ["resolve", "context", "loadConfig", "warn"])
            #expect(rig.warnings.first?.contains("wardenrun setup") == true)
        }
    }

    @Test func anUnreadableProtectedItemIsAnErrorAndAsksNothing() throws {
        try withRig { rig in
            rig.configError = StoreError.unreadable(reason: "another signer")
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(!rig.trace.contains("approve"))
            #expect(rig.warnings.first?.contains("another signer") == true)
        }
    }

    @Test func aTooLongCommandIsDeniedWithTheFixedSentence() throws {
        try withRig { rig in
            let long = String(repeating: "x", count: 500)
            rig.executable = ResolvedExecutable(path: "/usr/local/bin/tool", argv: ["tool", long], sha256: ResolvedExecutable.sample.sha256)
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 77)
            #expect(!rig.trace.contains("approve"))
            #expect(!rig.trace.contains("fetch"))
            #expect(rig.warnings.first?.hasPrefix("command too long to review") == true)
            #expect(rig.audits.map(\.event) == [.denied])
            #expect(rig.audits.first?.item == "it-github")
        }
    }

    @Test func deniedTimedOutAndUnavailableAreAll77AndFetchNothing() throws {
        let cases: [(ApprovalDecision, AuditEventKind)] = [(.denied, .denied), (.timedOut, .timeout), (.unavailable(reason: "no Touch ID"), .error)]
        for (decision, kind) in cases {
            try withRig { rig in
                rig.decision = decision
                let code = RunFlow.run(rig.options, rig.steps())
                #expect(code == 77, "\(decision)")
                #expect(!rig.trace.contains("fetch"))
                #expect(!rig.trace.contains("spawn"))
                #expect(rig.audits.map(\.event) == [kind], "\(decision)")
                if case .unavailable(let reason) = decision { #expect(rig.warnings.contains { $0.contains(reason) }) }
            }
        }
    }

    @Test func aGateRefusalIs77() throws {
        let refusals: [GateRefusal] = [.anotherApprovalPending, .lockedOut(secondsLeft: 42), .stateUnavailable]
        for refusal in refusals {
            try withRig { rig in
                rig.approveError = refusal
                let code = RunFlow.run(rig.options, rig.steps())
                #expect(code == 77)
                #expect(rig.warnings.contains(refusal.message))
                #expect(rig.audits.map(\.event) == [.error])
                #expect(!rig.trace.contains("fetch"))
            }
        }
    }

    @Test func anUnexpectedApprovalErrorIs77AndNeverApproves() throws {
        try withRig { rig in
            struct Odd: Error {}
            rig.approveError = Odd()
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 77)
            #expect(!rig.trace.contains("fetch"))
        }
    }

    @Test func aVaultFailureAfterApprovalSpawnsNothingAndWipes() throws {
        try withRig { rig in
            rig.fetchError = BwError.itemNotFound
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(!rig.trace.contains("spawn"))
            #expect(rig.audits.map(\.event) == [.approved, .error])
            #expect(rig.warnings.first?.contains(BwError.itemNotFound.summary) == true)
            #expect(rig.password.isWiped, "the master password does not outlive the fetch")
        }
    }

    @Test func aMissingFieldAfterFetchSpawnsNothingAndWipesTheItem() throws {
        try withRig { rig in
            rig.options.env = [FieldBinding(name: "X", field: "nothere")]
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(!rig.trace.contains("spawn"))
            #expect(rig.fetchedItem?.isWipedForTesting == true)
            #expect(rig.audits.map(\.event) == [.approved, .error])
            #expect(rig.warnings.first?.contains("nothere") == true)
        }
    }

    @Test func aChangedExecutableAfterApprovalIsRefused() throws {
        try withRig { rig in
            rig.stillMatches = false
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(!rig.trace.contains("spawn"))
            #expect(rig.fetchedItem?.isWipedForTesting == true)
            #expect(rig.warnings.first?.contains("changed") == true)
            #expect(rig.audits.map(\.event) == [.approved, .error])
        }
    }

    @Test func theChildExitCodeIsPropagatedAndFinishedIsAudited() throws {
        for (result, expected) in [
            (ChildResult(end: .exited(3), exitCode: 3, duration: 2.0), Int32(3)),
            (ChildResult(end: .exited(255), exitCode: 255, duration: 0.1), 255),
            (ChildResult(end: .signaled(15), exitCode: 143, duration: 0.5), 143),
        ] {
            try withRig { rig in
                rig.childResult = result
                let code = RunFlow.run(rig.options, rig.steps())
                #expect(code == expected)
                let finished = try #require(rig.audits.last)
                #expect(finished.event == .finished)
                #expect(finished.exitStatus == expected)
                #expect(finished.durationMs == Int((result.duration * 1000).rounded()))
                #expect(finished.item == "it-github")
                #expect(finished.commandLine == nil, "the finished line carries no command and no values")
            }
        }
    }

    @Test func theApprovedEventDescribesTheCommandAndTheApprovalTextMatches() throws {
        try withRig { rig in
            rig.previousHash = String(repeating: "cd", count: 32)
            rig.writable = true
            _ = RunFlow.run(rig.options, rig.steps())
            let approved = try #require(rig.audits.first)
            #expect(approved.event == .approved)
            #expect(approved.item == "it-github")
            #expect(approved.commandLine == ["tool", "--flag", "arg"])
            #expect(approved.executable == "/usr/local/bin/tool")
            #expect(approved.executableSHA256 == String(repeating: "ab", count: 32))
            #expect(approved.cwd == "/work")
            #expect(approved.parentChain == ["zsh", "Terminal"])
            let text = try #require(rig.approvedText)
            #expect(text.contains("[writable exe]"))
            #expect(text.contains("[exe changed]"))
            #expect(text.contains("use secret \"it-github\" to run: /usr/local/bin/tool --flag arg"))
            #expect(text.contains("(from Terminal)"), "the shell between is skipped")
        }
    }

    @Test func tempFilesAreRemovedAfterASpawnFailure() throws {
        try withRig { rig in
            rig.options.files = [FieldBinding(name: "KEY_FILE", field: "password")]
            rig.spawnError = ChildError.spawnFailed(errno: EACCES)
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 126)
            #expect(rig.fileContentsAtSpawn["KEY_FILE"] == "P4SSWORD-VALUE", "the file existed while the child could start")
            #expect(rig.fileModeAtSpawn == 0o600)
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: rig.secretFilesParent)
            #expect(leftovers.isEmpty, "\(leftovers)")
            #expect(rig.audits.map(\.event) == [.approved, .error])
        }
    }

    @Test func tempFilesAreRemovedAfterASuccessfulRunToo() throws {
        try withRig { rig in
            rig.options.files = [FieldBinding(name: "KEY_FILE", field: "password")]
            _ = RunFlow.run(rig.options, rig.steps())
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: rig.secretFilesParent)
            #expect(leftovers.isEmpty)
        }
    }

    @Test func noFileFlagMeansNoSecretFilesAreMade() throws {
        try withRig { rig in
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(!rig.trace.contains("makeSecretFiles"))
        }
    }

    @Test func tooShortValuesWarnOnce() throws {
        try withRig { rig in
            rig.itemJSON = #"{"login":{"username":"abc","password":"xyz"},"fields":[]}"#
            rig.options.env = [FieldBinding(name: "A", field: "username"), FieldBinding(name: "B", field: "password")]
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 0)
            let notices = rig.warnings.filter { $0.contains("shorter than") }
            #expect(notices.count == 1, "\(rig.warnings)")
            #expect(rig.spawnedNeedleCount == 0)
        }
    }

    @Test func longValuesProduceNeedlesAndNoWarning() throws {
        try withRig { rig in
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(rig.spawnedNeedleCount > 0)
            #expect(rig.warnings.isEmpty, "\(rig.warnings)")
        }
    }

    @Test func noValueAppearsInAnyAuditEventOrWarning() throws {
        for scenario in 0..<5 {
            try withRig { rig in
                switch scenario {
                case 1: rig.decision = .denied
                case 2: rig.fetchError = BwError.unlockFailed(message: "the vault could not be unlocked")
                case 3: rig.stillMatches = false
                case 4: rig.spawnError = ChildError.spawnFailed(errno: ENOENT)
                default: break
                }
                rig.options.env = [FieldBinding(name: "A", field: "password")]
                _ = RunFlow.run(rig.options, rig.steps())
                let everything = (rig.audits.map { "\($0)" } + rig.warnings + [rig.approvedText ?? ""]).joined(separator: "\n")
                for value in ["P4SSWORD-VALUE", "TOKEN-VALUE-1", "master-password-VALUE"] {
                    #expect(!everything.contains(value), "scenario \(scenario) leaked \(value)")
                }
            }
        }
    }

    @Test func theItemIsWipedBeforeTheChildStarts() throws {
        try withRig { rig in
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(rig.itemWipedAtSpawn == true)
            #expect(rig.configPasswordWipedAtSpawn == true)
        }
    }

    @Test func variablesFilesAndStdinReachTheSpawnWithoutBecomingPlainStrings() throws {
        try withRig { rig in
            rig.options.env = [FieldBinding(name: "GH_TOKEN", field: "password")]
            rig.options.files = [FieldBinding(name: "KEY_FILE", field: "env:API_TOKEN")]
            rig.options.stdin = "password"
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(rig.spawnedSecretEnvironment == ["GH_TOKEN": "P4SSWORD-VALUE"])
            #expect(rig.spawnedStdin == "P4SSWORD-VALUE")
            let environment = try #require(rig.spawnedEnvironment)
            #expect(environment["PATH"] == "/usr/bin" && environment["HOME"] == "/Users/x", "the caller's environment is kept")
            #expect(environment["GH_TOKEN"] == nil, "a secret is not in the plain map")
            let path = try #require(environment["KEY_FILE"])
            #expect(path.hasPrefix(rig.secretFilesParent + "/"))
            #expect(!environment.values.contains("P4SSWORD-VALUE"))
        }
    }

    @Test func withoutFlagsTheEnvColonFieldsAreInjectedAndStdinIsInherited() throws {
        try withRig { rig in
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(rig.spawnedSecretEnvironment == ["API_TOKEN": "TOKEN-VALUE-1"])
            #expect(!rig.spawnedHadStdinData)
        }
    }

    @Test func nothingToInjectIsAnErrorBeforeAnythingStarts() throws {
        try withRig { rig in
            rig.itemJSON = #"{"login":{"password":"P4SSWORD-VALUE"},"fields":[]}"#
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(!rig.trace.contains("spawn"))
            #expect(rig.warnings.first?.contains("nothing to inject") == true)
        }
    }

    @Test func resolveErrorsMapToTheShellExitCodesAndAskNothing() throws {
        let cases: [(ExecError, Int32)] = [
            (.notFound("tool"), 127), (.notExecutable("tool"), 126), (.notRegularFile("tool"), 126),
            (.emptyCommand, 64), (.nulInArgument(index: 2), 64),
        ]
        for (error, expected) in cases {
            try withRig { rig in
                rig.resolveError = error
                let code = RunFlow.run(rig.options, rig.steps())
                #expect(code == expected, "\(error)")
                #expect(rig.trace == ["resolve", "warn"], "\(error)")
            }
        }
    }

    @Test func aSpawnThatFindsNothingIs127() throws {
        try withRig { rig in
            rig.spawnError = ChildError.spawnFailed(errno: ENOENT)
            #expect(RunFlow.run(rig.options, rig.steps()) == 127)
        }
    }

    @Test func theApprovalTextAndTheAuditLineSayWhereTheSecretGoes() throws {
        try withRig { rig in
            rig.options.env = [FieldBinding(name: "API_TOKEN", field: "password")]
            rig.options.files = [FieldBinding(name: "CERT_FILE", field: "password")]
            rig.options.stdin = "password"
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(rig.approvedText?.contains("use secret \"it-github\" as $API_TOKEN, file $CERT_FILE, stdin to run: ") == true)
            let approved = try #require(rig.audits.first { $0.event == .approved })
            #expect(approved.injected == ["$API_TOKEN", "file $CERT_FILE", "stdin"])
        }
    }

    @Test func withoutFlagsNothingIsClaimedAboutTheTargets() throws {
        try withRig { rig in
            _ = RunFlow.run(rig.options, rig.steps())
            #expect(rig.approvedText?.contains(" as ") == false)
            #expect(rig.audits.first?.injected == nil)
        }
    }

    @Test func theSecretFilesAreGoneBeforeTheFinishedLineIsWritten() throws {
        try withRig { rig in
            rig.options.files = [FieldBinding(name: "KEY_FILE", field: "password")]
            #expect(RunFlow.run(rig.options, rig.steps()) == 0)
            #expect(rig.fileContentsAtSpawn["KEY_FILE"] == "P4SSWORD-VALUE")
            #expect(rig.entriesWhenFinishedWasWritten == [], "\(String(describing: rig.entriesWhenFinishedWasWritten))")
        }
    }

    @Test func notBeingAbleToMakeAPipeIsAnOrdinaryFailureNotACommandThatCannotRun() throws {
        try withRig { rig in
            rig.spawnError = ChildError.pipeFailed(errno: EMFILE)
            #expect(RunFlow.run(rig.options, rig.steps()) == 1)
            #expect(rig.audits.map(\.event) == [.approved, .error])
        }
    }

    @Test func anExitStatusThatCannotBeCollectedIsAFailureOfWardenrunWithOneSentence() throws {
        try withRig { rig in
            rig.spawnError = ChildError.waitFailed(errno: ECHILD)
            #expect(RunFlow.run(rig.options, rig.steps()) == 1)
            #expect(rig.warnings.first?.contains("exit status could not be collected") == true)
            #expect(rig.audits.map(\.event) == [.approved, .error])
        }
    }

    @Test func totpIsReportedAsNotSupported() throws {
        try withRig { rig in
            rig.options.env = [FieldBinding(name: "X", field: "totp")]
            let code = RunFlow.run(rig.options, rig.steps())
            #expect(code == 1)
            #expect(rig.warnings.first?.contains("totp") == true)
        }
    }
}

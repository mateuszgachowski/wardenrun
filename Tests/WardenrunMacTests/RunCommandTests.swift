#if canImport(Darwin)
import Darwin
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

private final class FakeStore: SecretStore, @unchecked Sendable {
    let tierDescription = "test tier"
    var config: ProtectedConfig?
    func load() throws -> ProtectedConfig? { config }
    func save(_ config: ProtectedConfig) throws { self.config = config }
    func erase() throws { config = nil }
}

private final class FakeApprover: Approver, @unchecked Sendable {
    private let lock = NSLock()
    private var _texts: [String] = []
    var decision: ApprovalDecision = .approved
    var texts: [String] { lock.lock(); defer { lock.unlock() }; return _texts }
    func approve(reason: String, timeout: TimeInterval) -> ApprovalDecision {
        lock.lock(); _texts.append(reason); lock.unlock()
        return decision
    }
}

private struct FakeInspector: ProcessInspector {
    var names: [String]
    func parentChain(of pid: Int32) -> [ProcessRecord] {
        names.enumerated().map { ProcessRecord(pid: Int32($0.offset + 100), path: "/usr/bin/" + $0.element) }
    }
}

private struct NoSignature: BwSignatureChecker {
    func check(path: String, teamID: String) throws {}
    func checkRunning(pid: Int32, teamID: String) throws {}
}

private final class Sink: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: [UInt8] = []
    func add(_ more: [UInt8]) { lock.lock(); bytes += more; lock.unlock() }
    var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: bytes, as: UTF8.self) }
}

private func config(password: String = "master-password-VALUE") throws -> ProtectedConfig {
    try ProtectedConfig(serverURL: URL(string: "https://vault.example")!, accountEmail: "a@b.example",
                        organizationID: "org-1", collectionIDs: ["col-1"],
                        masterPassword: SecretBuffer(copying: Array(password.utf8)),
                        bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/bw"))
}

struct CommandSupportTests {
    @Test func isWritableIsTrueForAUserFileAndFolderAndFalseForASystemProgram() throws {
        try withTemp { dir in
            let file = dir + "/tool"
            FileManager.default.createFile(atPath: file, contents: Data())
            #expect(CommandSupport.isWritable(path: file))
            #expect(CommandSupport.isWritable(path: dir))
            // a read-only file in a writable folder can still be replaced
            chmod(file, 0o500)
            #expect(CommandSupport.isWritable(path: file))
        }
        // a file you can write inside a folder you cannot
        try withTemp { dir in
            let folder = dir + "/locked"
            try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
            let file = folder + "/tool"
            FileManager.default.createFile(atPath: file, contents: Data())
            chmod(folder, 0o500)
            defer { chmod(folder, 0o700) }
            #expect(CommandSupport.isWritable(path: file))
        }
        #expect(!CommandSupport.isWritable(path: "/usr/bin/true"))
        #expect(!CommandSupport.isWritable(path: "/bin/sh"))
    }

    @Test func theUserTemporaryDirectoryIsPrivateAndNotTheOneTheEnvironmentNames() throws {
        let saved = getenv("TMPDIR").map { String(cString: $0) }
        setenv("TMPDIR", "/tmp/not-this-one", 1)
        defer { if let saved { setenv("TMPDIR", saved, 1) } else { unsetenv("TMPDIR") } }
        let path = CommandSupport.userTemporaryDirectory()
        #expect(path.hasPrefix("/"))
        #expect(!path.hasPrefix("/tmp/not-this-one"))
        var info = stat()
        #expect(stat(path, &info) == 0)
        #expect(info.st_uid == getuid())
        #expect(info.st_mode & 0o077 == 0, "mode is \(String(info.st_mode & 0o777, radix: 8))")
    }

    @Test func parentNamesAreTheLastPathComponentsNearestFirst() {
        #expect(CommandSupport.parentNames(FakeInspector(names: ["zsh", "node"])) == ["zsh", "node"])
        #expect(CommandSupport.parentNames(FakeInspector(names: [])).isEmpty)
    }

    @Test func theRedactorMasksTheCurrentValuesAndPassesTheRestThrough() {
        let redactor = Redactor()
        #expect(redactor.redact("nothing to hide SECRET-VALUE-1") == "nothing to hide SECRET-VALUE-1")
        redactor.set(MaskNeedles.plan(for: [MaskSecret(name: "it", value: Array("SECRET-VALUE-1".utf8))]).needles)
        #expect(redactor.redact("cmd SECRET-VALUE-1 end") == "cmd [REDACTED:it] end")
        redactor.set([])
        #expect(redactor.redact("SECRET-VALUE-1") == "SECRET-VALUE-1")
    }

    private func withTemp(_ body: (String) throws -> Void) throws {
        let path = NSTemporaryDirectory() + "wardenrun-test-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: path) }
        try body(path)
    }
}

@Suite(.serialized)
struct SignalWatchTests {
    @Test func stoppingWithoutRestoringLeavesTheNewHandlerUntilTheOriginalsAreAskedFor() {
        var handler = sigaction()
        handler.__sigaction_u.__sa_sigaction = { _, _, _ in }
        handler.sa_flags = SA_SIGINFO
        sigemptyset(&handler.sa_mask)
        let watch = SignalWatch(signals: [SIGUSR2]) { _ in }
        sigaction(SIGUSR2, &handler, nil)                 // what ChildRunner does before the hand-over
        watch.stop(restoreHandlers: false)
        var current = sigaction()
        sigaction(SIGUSR2, nil, &current)
        #expect((current.sa_flags & SA_SIGINFO) != 0, "the runner's handler survived the hand-over")
        watch.restoreOriginals()
        sigaction(SIGUSR2, nil, &current)
        #expect((current.sa_flags & SA_SIGINFO) == 0, "the original disposition is back")
    }

    @Test func theDefaultSetIsEveryForwardedSignal() {
        // Until the command exists, QUIT, USR1 and USR2 would otherwise kill wardenrun with a
        // secret file on disk and an unlocked bw behind it.
        #expect(Set(SignalWatch.defaultSignals) == Set(ChildRunner.forwardedSignals))
    }

    @Test func aSignalWhileWatchingIsReportedAndDoesNotKillTheProcess() throws {
        let count = Box(0)
        let watch = SignalWatch(signals: [SIGUSR2]) { _ in count.value += 1 }
        defer { watch.stop() }
        kill(getpid(), SIGUSR2)
        let deadline = Date().addingTimeInterval(5)
        while watch.fired == nil && Date() < deadline { usleep(5_000) }
        #expect(watch.fired == SIGUSR2)
        #expect(count.value == 1)
    }

    @Test func stopPutsTheOldHandlerBack() throws {
        func handler(_ signal: Int32) -> Int {
            var action = sigaction()
            sigaction(signal, nil, &action)
            return action.__sigaction_u.__sa_handler.map { unsafeBitCast($0, to: Int.self) } ?? 0
        }
        signal(SIGUSR2, SIG_DFL)
        let before = handler(SIGUSR2)
        let watch = SignalWatch(signals: [SIGUSR2]) { _ in }
        #expect(handler(SIGUSR2) == 1, "ignored while watching")
        watch.stop()
        watch.stop()
        #expect(handler(SIGUSR2) == before)
    }

    @Test func noSignalMeansNothingFired() {
        let watch = SignalWatch(signals: [SIGUSR2]) { _ in }
        defer { watch.stop() }
        #expect(watch.fired == nil)
    }
}

@Suite(.serialized)
struct VaultSessionTests {
    private func vault() throws -> BwVault {
        let dir = NSTemporaryDirectory() + "wardenrun-test-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return BwVault(config: try config(), appDataDir: dir + "/bw", home: dir, lockPath: dir + "/bw.lock",
                       signature: NoSignature())
    }

    @Test func anInterruptWhileTheSessionIsWatchedCancelsTheVaultAndIsReported() throws {
        let vault = try vault()
        let session = VaultSession()
        session.begin(vault)
        kill(getpid(), SIGHUP)
        // the vault refuses to start anything once it is cancelled; before that it fails otherwise
        var cancelled = false
        let deadline = Date().addingTimeInterval(5)
        while !cancelled && Date() < deadline {
            do { _ = try vault.fetch(itemName: "x") } catch BwError.cancelled { cancelled = true } catch {}
            if !cancelled { usleep(5_000) }
        }
        #expect(cancelled)
        #expect(session.end())
        #expect(!session.end(), "reported once")
    }

    @Test func handingOverLeavesTheRunnersHandlersAndThePlainEndPutsTheOriginalsBack() throws {
        func disposition() -> Int {
            var current = sigaction()
            sigaction(SIGUSR2, nil, &current)
            return unsafeBitCast(current.__sigaction_u.__sa_handler, to: Int.self)
        }
        let session = VaultSession()
        session.begin(nil)
        #expect(disposition() == 1, "the watch ignores the signal and listens through a dispatch source")
        // what ChildRunner does between the watch and the hand-over
        var runner = sigaction()
        runner.__sigaction_u.__sa_sigaction = { _, _, _ in }
        runner.sa_flags = SA_SIGINFO
        sigemptyset(&runner.sa_mask)
        sigaction(SIGUSR2, &runner, nil)
        #expect(!session.end(handingOver: true))
        var current = sigaction()
        sigaction(SIGUSR2, nil, &current)
        #expect((current.sa_flags & SA_SIGINFO) != 0, "the runner's handler was not overwritten by the watch's old one")
        #expect(!session.end())
        #expect(disposition() == 0, "back to the default once the run is over")
    }

    @Test func noInterruptMeansEndSaysSo() throws {
        let session = VaultSession()
        session.begin(try vault())
        #expect(!session.end())
        #expect(!VaultSession().end())
    }
}

final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

@Suite(.serialized)
struct RunCommandTests {
    private struct Rig {
        let home: String
        let store = FakeStore()
        let approver = FakeApprover()
        let out = Sink(), err = Sink(), errors = Sink()
        var paths: WardenrunPaths { WardenrunPaths(home: home) }
    }

    private func withRig(_ body: (Rig) throws -> Void) throws {
        let path = NSTemporaryDirectory() + "wardenrun-test-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: path) }
        try body(Rig(home: path))
    }

    private func options(_ item: String = "it-github", command: [String]) -> RunOptions {
        RunOptions(item: item, env: [], files: [], stdin: nil, command: command)
    }

    private let itemJSON = #"{"login":{"password":"P4SSWORD-VALUE"},"fields":[{"name":"env:API_TOKEN","value":"SECRET-TOKEN-VALUE-99"}]}"#

    private func run(_ rig: Rig, _ options: RunOptions, environment: [String: String] = ["PATH": "/bin:/usr/bin"],
                     fetch: (@Sendable (ProtectedConfig, String) throws -> BwFetchedItem)? = nil) -> Int32 {
        let errors = rig.errors
        return RunCommand.run(options: options, environment: environment, paths: rig.paths, store: rig.store,
                              approver: rig.approver, inspector: FakeInspector(names: ["zsh", "claude"]), signature: NoSignature(),
                              errorOutput: { errors.add([UInt8](($0 + "\n").utf8)) }, fetchOverride: fetch,
                              standardOutput: { rig.out.add($0) }, standardError: { rig.err.add($0) })
    }

    private func auditLines(_ rig: Rig) throws -> [[String: Any]] {
        guard let text = try? String(contentsOfFile: rig.paths.auditLog, encoding: .utf8) else { return [] }
        return try text.split(separator: "\n").map { try #require(JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]) }
    }

    @Test func notSetUpAsksNothingAndSaysSo() throws {
        try withRig { rig in
            let code = run(rig, options(command: ["/usr/bin/true"]))
            #expect(code == 1)
            #expect(rig.approver.texts.isEmpty)
            #expect(rig.errors.text.contains("wardenrun setup"))
            #expect(rig.errors.text.hasPrefix("wardenrun: "))
        }
    }

    @Test func aDeniedRunIs77FetchesNothingAndIsLogged() throws {
        try withRig { rig in
            rig.store.config = try config()
            rig.approver.decision = .denied
            let fetched = Box(false)
            let code = run(rig, options(command: ["/usr/bin/true"])) { _, _ in fetched.value = true; throw BwError.itemNotFound }
            #expect(code == 77)
            #expect(!fetched.value)
            let lines = try auditLines(rig)
            #expect(lines.map { $0["event"] as? String } == ["denied"])
            #expect(lines.first?["tier"] as? String == "test tier")
            #expect(lines.first?["item"] as? String == "it-github")
            var info = stat()
            #expect(stat(rig.paths.auditLog, &info) == 0)
            #expect(info.st_mode & 0o777 == 0o600)
        }
    }

    @Test func anApprovedRunInjectsRunsMasksAndLogsWithoutTheValue() throws {
        try withRig { rig in
            rig.store.config = try config()
            let script = "echo \"token=$API_TOKEN\"; echo \"err:$API_TOKEN\" >&2; exit 3"
            let json = itemJSON
            let code = run(rig, options(command: ["/bin/sh", "-c", script])) { _, _ in
                BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "i-1", name: "it-github")
            }
            #expect(code == 3)
            #expect(rig.out.text == "token=[REDACTED:it-github]\n")
            #expect(rig.err.text == "err:[REDACTED:it-github]\n")
            let sheet = try #require(rig.approver.texts.first)
            #expect(sheet.contains("use secret \"it-github\" to run: /bin/sh -c"))
            #expect(sheet.contains("(from claude)"), "the shell parent is skipped: \(sheet)")
            #expect(sheet.contains("[shell -c]"))
            let lines = try auditLines(rig)
            #expect(lines.map { $0["event"] as? String } == ["approved", "finished"])
            #expect(lines.last?["exit_status"] as? Int == 3)
            let raw = try String(contentsOfFile: rig.paths.auditLog, encoding: .utf8)
            for value in ["SECRET-TOKEN-VALUE-99", "P4SSWORD-VALUE", "master-password-VALUE"] { #expect(!raw.contains(value)) }
            #expect(rig.errors.text.isEmpty, Comment(rawValue: rig.errors.text))
        }
    }

    @Test func aSecondRunSeesTheFirstRunsHashAndFlagsAChange() throws {
        try withRig { rig in
            rig.store.config = try config()
            let json = itemJSON
            let fetch: @Sendable (ProtectedConfig, String) throws -> BwFetchedItem = { _, _ in
                BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "i-1", name: "it-github")
            }
            // a user-owned program, changed between two approvals
            let program = rig.home + "/prog.sh"
            try "#!/bin/sh\nexit 0\n".write(toFile: program, atomically: true, encoding: .utf8)
            chmod(program, 0o755)
            _ = run(rig, options(command: [program]), fetch: fetch)
            try "#!/bin/sh\nexit 1\n".write(toFile: program, atomically: true, encoding: .utf8)
            _ = run(rig, options(command: [program]), fetch: fetch)
            #expect(rig.approver.texts.count == 2)
            #expect(!rig.approver.texts[0].contains("[exe changed]"))
            #expect(rig.approver.texts[1].contains("[exe changed]"))
            #expect(rig.approver.texts[1].contains("[writable exe]"))
        }
    }

    @Test func withoutPathInTheEnvironmentTheSystemFoldersAreSearched() throws {
        try withRig { rig in
            rig.store.config = try config()
            rig.approver.decision = .denied
            let code = run(rig, options(command: ["true"]), environment: [:])
            #expect(code == 77, "the program was found (denied, not 127)")
            #expect(rig.approver.texts.first?.contains("to run: /usr/bin/true") == true)
        }
    }

    @Test func anInterruptBeforeTheCommandStartsEndsTheRunAndStartsNothing() throws {
        try withRig { rig in
            rig.store.config = try config()
            let json = itemJSON
            let marker = rig.home + "/started"
            let code = run(rig, options(command: ["/usr/bin/touch", marker])) { _, _ in
                kill(getpid(), SIGHUP)
                usleep(400_000)      // the watch sees it on its own queue
                return BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "i-1", name: "it-github")
            }
            #expect(code == 1)
            #expect(rig.errors.text.contains("interrupted"))
            #expect(!FileManager.default.fileExists(atPath: marker), "the command must not have started")
            let lines = try auditLines(rig)
            #expect(lines.map { $0["event"] as? String } == ["approved", "error"])
        }
    }

    @Test func aSecretTypedIntoTheCommandLineIsMaskedInTheAuditLinesAfterTheFetch() throws {
        try withRig { rig in
            rig.store.config = try config()
            let json = itemJSON
            // a program that cannot start (bad interpreter), so that the failure is audited with its command line
            let program = rig.home + "/broken.sh"
            try "#!/nonexistent/interpreter\n".write(toFile: program, atomically: true, encoding: .utf8)
            chmod(program, 0o755)
            let code = run(rig, options(command: [program, "SECRET-TOKEN-VALUE-99"])) { _, _ in
                BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "i-1", name: "it-github")
            }
            #expect(code == 127 || code == 126)
            let lines = try auditLines(rig)
            let failure = try #require(lines.last)
            #expect(failure["event"] as? String == "error")
            let commandLine = failure["command_line"] as? [String]
            #expect(commandLine == [program, "[REDACTED:it-github]"], "\(String(describing: commandLine))")
        }
    }

    @Test func aMissingProgramIs127BeforeAnythingIsAsked() throws {
        try withRig { rig in
            rig.store.config = try config()
            let code = run(rig, options(command: ["definitely-not-a-program-xyz"]))
            #expect(code == 127)
            #expect(rig.approver.texts.isEmpty)
        }
    }

    @Test func theChildDoesNotInheritTheMasterPasswordOrTheItem() throws {
        try withRig { rig in
            rig.store.config = try config()
            let json = itemJSON
            let code = run(rig, options(command: ["/usr/bin/env"])) { _, _ in
                BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "i-1", name: "it-github")
            }
            #expect(code == 0)
            #expect(!rig.out.text.contains("master-password-VALUE"))
            #expect(rig.out.text.contains("API_TOKEN=[REDACTED:it-github]"))
            #expect(rig.out.text.contains("PATH=/bin:/usr/bin"), "the caller's environment is kept")
        }
    }
}
#endif

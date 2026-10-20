#if canImport(Darwin)
import Darwin
import Foundation
import WardenrunCore

/// Masks the values of the current run in every string the audit log writes. The needles are set
/// once the secrets are known, which is before the command starts.
final class Redactor: @unchecked Sendable {
    private let lock = NSLock()
    private var needles: [Needle] = []

    func set(_ needles: [Needle]) {
        lock.lock(); defer { lock.unlock() }
        self.needles = needles
    }

    func redact(_ text: String) -> String {
        lock.lock()
        let current = needles
        lock.unlock()
        if current.isEmpty { return text }
        return String(decoding: StreamMasker.maskAll(Array(text.utf8), needles: current), as: UTF8.self)
    }
}

/// Helpers the `run` and `new` commands share.
enum CommandSupport {
    /// True when the current user could replace the program: the file itself or its folder can
    /// be written (so the approval sheet says `[writable exe]`).
    static func isWritable(path: String) -> Bool {
        if access(path, W_OK) == 0 { return true }
        let directory = (path as NSString).deletingLastPathComponent
        return access(directory.isEmpty ? "." : directory, W_OK) == 0
    }

    /// The per-user temporary folder of the system (mode 0700), not `$TMPDIR`, which the caller controls.
    static func userTemporaryDirectory() -> String {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        if confstr(_CS_DARWIN_USER_TEMP_DIR, &buffer, buffer.count) > 0 {
            var path = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
            if path.hasPrefix("/") { return path }
        }
        return NSTemporaryDirectory()
    }

    /// Short names of the parent processes, nearest first.
    static func parentNames(_ inspector: ProcessInspector) -> [String] {
        inspector.parentChain(of: getpid()).map { ($0.path as NSString).lastPathComponent }
    }

    /// `write(2)` to a descriptor until everything is out or the other end is gone. Not
    /// `FileHandle`, which raises an exception on a closed pipe.
    static func writeAll(_ descriptor: Int32, _ bytes: [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            let count = bytes[offset...].withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { return }
            offset += count
        }
    }
}

/// `wardenrun run` on a Mac: plugs the keychain item, Touch ID, `bw`, the process inspector and
/// the child runner into `RunFlow`. All decisions live in `RunFlow`; this file only connects things.
public enum RunCommand {
    /// The child's own exit code, or 1, 64, 77, 126, 127 (see `RunExit`).
    public static func run(options: RunOptions, environment: [String: String], paths: WardenrunPaths,
                           store: SecretStore, approver: Approver = BiometricApprover(),
                           inspector: ProcessInspector = MacProcessInspector(),
                           signature: BwSignatureChecker = SecuritySignatureChecker(),
                           errorOutput: @escaping @Sendable (String) -> Void) -> Int32 {
        run(options: options, environment: environment, paths: paths, store: store, approver: approver,
            inspector: inspector, signature: signature, errorOutput: errorOutput,
            fetchOverride: nil, standardOutput: { CommandSupport.writeAll(STDOUT_FILENO, $0) },
            standardError: { CommandSupport.writeAll(STDERR_FILENO, $0) })
    }

    /// The same with the three seams the tests use: the vault fetch and the two places the
    /// child's masked output goes.
    static func run(options: RunOptions, environment: [String: String], paths: WardenrunPaths,
                    store: SecretStore, approver: Approver, inspector: ProcessInspector,
                    signature: BwSignatureChecker, errorOutput: @escaping @Sendable (String) -> Void,
                    fetchOverride: (@Sendable (ProtectedConfig, String) throws -> BwFetchedItem)?,
                    standardOutput: @escaping @Sendable ([UInt8]) -> Void,
                    standardError: @escaping @Sendable ([UInt8]) -> Void) -> Int32 {
        let gate = ApprovalGate(stateDirectory: paths.stateDirectory)
        let redactor = Redactor()
        let audit = AuditLog(path: paths.auditLog, redactor: { redactor.redact($0) })
        let session = VaultSession()
        defer { session.end() }

        let steps = RunSteps(
            resolve: { options in
                try ExecResolver.resolve(argv: options.command, searchPath: environment["PATH"] ?? "/usr/bin:/bin",
                                         cwd: FileManager.default.currentDirectoryPath)
            },
            context: {
                RunContext(cwd: FileManager.default.currentDirectoryPath, parentChain: CommandSupport.parentNames(inspector),
                           callerEnvironment: environment, executableIsWritable: { CommandSupport.isWritable(path: $0) })
            },
            loadConfig: { try store.load() },
            previousHash: { item, executable in AuditLog.lastApprovedHash(path: paths.auditLog, item: item, executable: executable) },
            approve: { text in try gate.guarded { approver.approve(reason: text, timeout: 60) } },
            fetch: { config, itemName in
                if let fetchOverride {
                    session.begin(nil)
                    return try fetchOverride(config, itemName)
                }
                let vault = BwVault(config: config, appDataDir: paths.bwAppData, home: paths.home,
                                    lockPath: paths.lockFile, signature: signature)
                session.begin(vault)
                return try vault.fetch(itemName: itemName)
            },
            makeSecretFiles: { SecretFiles(parent: CommandSupport.userTemporaryDirectory()) },
            stillMatches: { ExecResolver.stillMatches($0) },
            spawn: { executable, plain, secret, stdin, needles in
                redactor.set(needles)
                // The child runner installs its own signal handlers and only then calls the hook,
                // which hands the signals over: an interrupt that arrived before ends the run, and
                // there is no moment in which a signal would find no handler.
                return try ChildRunner.run(executable: executable, environment: plain, secretEnvironment: secret,
                                           stdin: stdin, needles: needles,
                                           beforeStart: { if session.end(handingOver: true) { throw RunError.interrupted } },
                                           out: standardOutput, err: standardError)
            },
            audit: { event in
                var event = event
                event.tier = store.tierDescription
                do { try audit.append(event) } catch { errorOutput("wardenrun: the audit log could not be written") }
            },
            warn: { errorOutput("wardenrun: " + $0) })
        return RunFlow.run(options, steps)
    }
}

/// The `bw` session of one command, and the watch that ends it when the person interrupts.
final class VaultSession: @unchecked Sendable {
    private let lock = NSLock()
    private var watch: SignalWatch?
    /// A watch that handed the signals over to `ChildRunner` and still owes the originals back.
    private var handedOver: SignalWatch?

    /// `vault` is the one to cancel on an interrupt; tests that bring their own fetch pass nil.
    func begin(_ vault: BwVault?) {
        let new = SignalWatch { _ in vault?.cancel() }
        lock.lock()
        let old = watch
        watch = new
        lock.unlock()
        old?.stop()
    }

    /// Stops watching; true when an interrupt arrived while it was on. With `handingOver` the
    /// handlers are left alone (the child runner has installed its own) and the originals come
    /// back at the next plain `end()`.
    @discardableResult
    func end(handingOver: Bool = false) -> Bool {
        lock.lock()
        let current = watch
        watch = nil
        let pending = handedOver
        handedOver = handingOver ? current : nil
        lock.unlock()
        pending?.restoreOriginals()
        let fired = current?.fired != nil
        current?.stop(restoreHandlers: !handingOver)
        return fired
    }
}
#endif

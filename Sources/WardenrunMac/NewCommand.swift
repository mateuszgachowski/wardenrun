#if canImport(Darwin)
import Darwin
import Foundation
import WardenrunCore

/// `wardenrun new` on a Mac: plugs the keychain item, Touch ID, the random source and `bw` into
/// `NewFlow`. All decisions live in `NewFlow`; this file only connects things.
public enum NewCommand {
    /// 0 created, 1 failed, 77 not approved.
    public static func run(options: NewOptions, environment: [String: String], paths: WardenrunPaths,
                           store: SecretStore, approver: Approver = BiometricApprover(),
                           inspector: ProcessInspector = MacProcessInspector(),
                           signature: BwSignatureChecker = SecuritySignatureChecker(),
                           random: RandomSource = SecureRandom(),
                           output: (String) -> Void, errorOutput: @escaping @Sendable (String) -> Void) -> Int32 {
        run(options: options, environment: environment, paths: paths, store: store, approver: approver,
            inspector: inspector, signature: signature, random: random, createOverride: nil,
            output: output, errorOutput: errorOutput)
    }

    /// The same with the one seam the tests use: the vault call that stores the item.
    static func run(options: NewOptions, environment: [String: String], paths: WardenrunPaths,
                    store: SecretStore, approver: Approver, inspector: ProcessInspector,
                    signature: BwSignatureChecker, random: RandomSource,
                    createOverride: (@Sendable (ProtectedConfig, NewOptions, SecretBuffer) throws -> String)?,
                    output: (String) -> Void, errorOutput: @escaping @Sendable (String) -> Void) -> Int32 {
        let gate = ApprovalGate(stateDirectory: paths.stateDirectory)
        let audit = AuditLog(path: paths.auditLog, redactor: { $0 })
        let session = VaultSession()
        defer { session.end() }

        let steps = NewSteps(
            context: { (cwd: FileManager.default.currentDirectoryPath, parentChain: CommandSupport.parentNames(inspector)) },
            loadConfig: { try store.load() },
            approve: { text in try gate.guarded { approver.approve(reason: text, timeout: 60) } },
            generate: { length, charset in try PasswordGenerator.generate(length: length, charset: charset, random: random) },
            create: { config, options, password in
                if let createOverride {
                    session.begin(nil)
                    return try createOverride(config, options, password)
                }
                let vault = BwVault(config: config, appDataDir: paths.bwAppData, home: paths.home,
                                    lockPath: paths.lockFile, signature: signature)
                session.begin(vault)
                return try vault.createItem(name: options.name, username: options.username, uri: options.uri,
                                            secret: password, asEnvVariable: options.env)
            },
            audit: { event in
                var event = event
                event.tier = store.tierDescription
                do { try audit.append(event) } catch { errorOutput("wardenrun: the audit log could not be written") }
            },
            warn: { errorOutput("wardenrun: " + $0) })
        let outcome = NewFlow.run(options, steps)
        if let line = outcome.line { output(line) }
        return outcome.code
    }
}
#endif

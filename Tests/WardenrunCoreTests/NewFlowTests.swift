import Foundation
import Testing
@testable import WardenrunCore

private final class NewRig: @unchecked Sendable {
    private let lock = NSLock()
    private var _trace: [String] = []
    private var _audits: [AuditEvent] = []
    private var _warnings: [String] = []
    var trace: [String] { lock.lock(); defer { lock.unlock() }; return _trace }
    var audits: [AuditEvent] { lock.lock(); defer { lock.unlock() }; return _audits }
    var warnings: [String] { lock.lock(); defer { lock.unlock() }; return _warnings }
    func note(_ text: String) { lock.lock(); _trace.append(text); lock.unlock() }

    var options = NewOptions(name: "deploy-token", username: nil, uri: nil, env: nil, length: 32, charset: .alnum)
    var configured = true
    var configError: Error?
    var decision: ApprovalDecision = .approved
    var approveError: Error?
    var generateError: Error?
    var createError: Error?
    var createdID = "11111111-2222-3333-4444-555555555555"
    var password = "GENERATED-PASSWORD-VALUE-1234567890"
    var collections = ["col-1", "col-2"]
    var masterPassword = SecretBuffer(copying: Array("master-password-VALUE".utf8))

    private(set) var approvedText: String?
    private(set) var generated: SecretBuffer?
    private(set) var generatedWith: (Int, PasswordCharset)?
    private(set) var createdWith: NewOptions?
    private(set) var passwordAtCreate: String?
    private(set) var passwordWipedAtEnd = false

    func steps() -> NewSteps {
        NewSteps(
            context: { [self] in note("context"); return (cwd: "/work", parentChain: ["zsh", "Terminal"]) },
            loadConfig: { [self] in
                note("loadConfig")
                if let configError { throw configError }
                guard configured else { return nil }
                return try ProtectedConfig(serverURL: URL(string: "https://vault.example")!, accountEmail: "a@b.example",
                                           organizationID: "org-1", collectionIDs: collections, masterPassword: masterPassword,
                                           bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/bw"))
            },
            approve: { [self] text in
                note("approve")
                approvedText = text
                if let approveError { throw approveError }
                return decision
            },
            generate: { [self] length, charset in
                note("generate")
                generatedWith = (length, charset)
                if let generateError { throw generateError }
                let buffer = SecretBuffer(copying: Array(password.utf8))
                generated = buffer
                return buffer
            },
            create: { [self] _, options, secret in
                note("create")
                createdWith = options
                passwordAtCreate = secret.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
                if let createError { throw createError }
                return createdID
            },
            audit: { [self] event in lock.lock(); _audits.append(event); lock.unlock(); note("audit:\(event.event.rawValue)") },
            warn: { [self] text in lock.lock(); _warnings.append(text); lock.unlock(); note("warn") })
    }
}

struct NewFlowTests {
    @Test func theStepsRunInOrder() {
        let rig = NewRig()
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.code == 0)
        #expect(rig.trace == ["context", "loadConfig", "approve", "generate", "create", "audit:new"])
        #expect(rig.generatedWith?.0 == 32 && rig.generatedWith?.1 == .alnum)
        #expect(rig.createdWith == rig.options)
        #expect(rig.passwordAtCreate == rig.password)
    }

    @Test func notSetUpAsksNothing() {
        let rig = NewRig()
        rig.configured = false
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.code == 1 && outcome.line == nil)
        #expect(!rig.trace.contains("approve") && !rig.trace.contains("generate") && !rig.trace.contains("create"))
        #expect(rig.warnings.first?.contains("wardenrun setup") == true)
    }

    @Test func anUnreadableProtectedItemAsksNothing() {
        let rig = NewRig()
        rig.configError = StoreError.unreadable(reason: "another signer")
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.code == 1)
        #expect(!rig.trace.contains("approve"))
    }

    @Test func deniedIs77AndCreatesNothing() {
        for (decision, kind) in [(ApprovalDecision.denied, AuditEventKind.denied), (.timedOut, .timeout), (.unavailable(reason: "no Touch ID"), .error)] {
            let rig = NewRig()
            rig.decision = decision
            let outcome = NewFlow.run(rig.options, rig.steps())
            #expect(outcome.code == 77, "\(decision)")
            #expect(outcome.line == nil)
            #expect(!rig.trace.contains("generate") && !rig.trace.contains("create"))
            #expect(rig.audits.map(\.event) == [kind])
        }
    }

    @Test func aGateRefusalIs77() {
        for refusal in [GateRefusal.anotherApprovalPending, .lockedOut(secondsLeft: 9), .stateUnavailable] {
            let rig = NewRig()
            rig.approveError = refusal
            let outcome = NewFlow.run(rig.options, rig.steps())
            #expect(outcome.code == 77)
            #expect(rig.warnings.contains(refusal.message))
            #expect(!rig.trace.contains("generate"))
        }
    }

    @Test func existingNameFailsWithoutCreating() {
        let rig = NewRig()
        rig.createError = BwError.alreadyExists
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.code == 1 && outcome.line == nil)
        #expect(rig.warnings.first?.contains("already exists") == true)
        #expect(rig.audits.map(\.event) == [.error])
        #expect(rig.generated?.isWiped == true)
    }

    @Test func aFailingGeneratorOrVaultFailsOnceAndWipesTheMasterPassword() {
        for scenario in 0..<2 {
            let rig = NewRig()
            if scenario == 0 { rig.generateError = PasswordError.invalidLength } else { rig.createError = BwError.timeout(phase: "x") }
            let outcome = NewFlow.run(rig.options, rig.steps())
            #expect(outcome.code == 1)
            #expect(rig.audits.map(\.event) == [.error])
            #expect(rig.masterPassword.isWiped)
        }
    }

    @Test func theLineHasNameIdAndCollectionAndNeverThePassword() {
        let rig = NewRig()
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.line == "created \"deploy-token\" (id 11111111-2222-3333-4444-555555555555) in col-1")
        #expect(outcome.line?.contains(rig.password) == false)
        #expect(rig.generated?.isWiped == true, "the password is wiped once it is stored")
        #expect(rig.masterPassword.isWiped)
    }

    @Test func aNameWithControlCharactersIsEscapedInTheLineAndTheSheet() {
        let rig = NewRig()
        rig.options.name = "bad\nname\u{202E}x"
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.line?.contains("\n") == false)
        #expect(outcome.line?.contains("\\n") == true)
        #expect(rig.approvedText?.contains("\n") == false)
        #expect(rig.approvedText?.unicodeScalars.contains { $0.value == 0x202E } == false)
    }

    @Test func theSheetNamesTheItemTheCollectionTheLengthAndTheOptionalParts() throws {
        let rig = NewRig()
        rig.options.username = "svc-user"
        rig.options.uri = "https://example.org/x"
        rig.options.env = "DEPLOY_TOKEN"
        rig.options.length = 48
        rig.options.charset = .full
        _ = NewFlow.run(rig.options, rig.steps())
        let text = try #require(rig.approvedText)
        #expect(text.hasPrefix("create item \"deploy-token\" in collection col-1"))
        #expect(text.contains("username \"svc-user\""))
        #expect(text.contains("uri \"https://example.org/x\""))
        #expect(text.contains("stored as env:DEPLOY_TOKEN"))
        #expect(text.contains("password of 48 characters"))
        #expect(text.contains("never shown"))
        #expect(text.contains("(from zsh)"))
        #expect(text.hasSuffix("[end]"))
        #expect(!text.contains(rig.password))
    }

    @Test func aRequestTooLongToReviewIsRefusedNotCut() {
        let rig = NewRig()
        rig.options.name = String(repeating: "n", count: 500)
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.code == 77)
        #expect(!rig.trace.contains("approve") && !rig.trace.contains("create"))
        #expect(rig.warnings.first?.contains("too long to review") == true)
        #expect(rig.audits.map(\.event) == [.denied])
    }

    @Test func noValueInAuditOrOutput() {
        for scenario in 0..<4 {
            let rig = NewRig()
            switch scenario {
            case 1: rig.decision = .denied
            case 2: rig.createError = BwError.alreadyExists
            case 3: rig.generateError = PasswordError.randomSourceExhausted
            default: break
            }
            let outcome = NewFlow.run(rig.options, rig.steps())
            let everything = (rig.audits.map { "\($0)" } + rig.warnings + [outcome.line ?? "", rig.approvedText ?? ""]).joined(separator: "\n")
            #expect(!everything.contains(rig.password), "scenario \(scenario)")
            #expect(!everything.contains("master-password-VALUE"), "scenario \(scenario)")
        }
    }

    @Test func theAuditEventNamesTheItemAndTheCallerNotAnyValue() throws {
        let rig = NewRig()
        _ = NewFlow.run(rig.options, rig.steps())
        let event = try #require(rig.audits.first)
        #expect(event.event == .new)
        #expect(event.item == "deploy-token")
        #expect(event.cwd == "/work")
        #expect(event.parentChain == ["zsh", "Terminal"])
        #expect(event.commandLine == nil)
    }

    @Test func theFirstAllowedCollectionIsTheOneUsed() {
        let rig = NewRig()
        rig.collections = ["first-col", "second-col"]
        let outcome = NewFlow.run(rig.options, rig.steps())
        #expect(outcome.line?.hasSuffix("in first-col") == true)
        #expect(rig.approvedText?.contains("collection first-col") == true)
    }
}

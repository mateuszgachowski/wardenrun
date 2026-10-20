import Foundation
import Testing
@testable import WardenrunCore

private let teamID = "LTZ2PFU5D6"
private let plannedPin = BwPin.signedRelease(teamID: teamID, path: "/home/u/.config/wardenrun/bin/bw")

/// Every step of the flow, recorded in order. A step can be made to fail by name.
private final class Rig: @unchecked Sendable {
    private let lock = NSLock()
    private var log_: [String] = []
    var log: [String] { lock.lock(); defer { lock.unlock() }; return log_ }
    var interactive = true
    var answers: [String: String] = ["server": "https://vault.example", "email": "me@example.test",
                                     "organization": "org-1", "collections": "col-1, col-2 ,"]
    var password = "master-pass-KNOWN-9"
    var existing: ProtectedConfig?
    var existingError: Error?
    var decision: ApprovalDecision = .approved
    var failAt: String?
    var failure: Error = SetupError.bwFailed(step: "login")
    var approvalTexts: [String] = []
    var audits: [AuditEvent] = []
    var saved: [ProtectedConfig] = []
    var askedDefaults: [String: String?] = [:]
    var unavailableReason: String?

    func record(_ step: String) { lock.lock(); log_.append(step); lock.unlock() }
    func maybeFail(_ step: String) throws { if failAt == step { throw failure } }

    func steps() -> SetupSteps {
        SetupSteps(
            isInteractive: interactive,
            plannedPin: plannedPin,
            ask: { [self] question, fallback in
                record("ask:" + question)
                askedDefaults[question] = .some(fallback)
                try maybeFail("ask:" + question)
                return answers[question] ?? ""
            },
            readPassword: { [self] in
                record("password")
                try maybeFail("password")
                return SecretBuffer(copying: Array(password.utf8))
            },
            existing: { [self] in
                record("existing")
                if let existingError { throw existingError }
                return existing
            },
            approve: { [self] text in
                record("approve")
                approvalTexts.append(text)
                try maybeFail("approve")
                return decision
            },
            install: { [self] in
                record("install")
                try maybeFail("install")
                return plannedPin
            },
            configureBw: { [self] _ in record("configure"); try maybeFail("configure") },
            verify: { [self] _ in record("verify"); try maybeFail("verify") },
            commitProfile: { [self] in record("commit"); try maybeFail("commit") },
            discardProfile: { [self] in record("discard") },
            save: { [self] config in record("save"); try maybeFail("save"); saved.append(config) },
            audit: { [self] event in record("audit"); audits.append(event) })
    }
}

private func oldConfig() throws -> ProtectedConfig {
    try ProtectedConfig(serverURL: URL(string: "https://old.example")!, accountEmail: "old@example.test",
                        organizationID: "org-old", collectionIDs: ["col-old"],
                        masterPassword: SecretBuffer(copying: Array("old-pass-1234".utf8)), bwPin: plannedPin,
                        nodeExtraCACerts: nil, httpsProxy: nil)
}

struct SetupFlowTests {
    @Test func theStepsRunInTheDocumentedOrderAndSaveComesAfterVerify() throws {
        let rig = Rig()
        let result = try SetupFlow.run(rig.steps())
        #expect(rig.log == ["existing", "ask:server", "ask:email", "ask:organization", "ask:collections", "password",
                            "approve", "install", "configure", "verify", "commit", "save", "audit", "discard"])
        #expect(result.contains("vault.example"))
        #expect(!result.contains("KNOWN"))
    }

    @Test func withoutATerminalNothingIsAskedOrRead() {
        let rig = Rig()
        rig.interactive = false
        #expect(throws: SetupError.notInteractive) { _ = try SetupFlow.run(rig.steps()) }
        #expect(rig.log.isEmpty)
    }

    @Test func collectionsAreSplitOnCommasTrimmedAndEmptyOnesDropped() throws {
        let rig = Rig()
        _ = try SetupFlow.run(rig.steps())
        let text = try #require(rig.approvalTexts.first)
        #expect(text.contains("col-1, col-2"))
    }

    @Test func anInvalidAnswerStopsBeforeAnyApprovalOrChange() {
        let rig = Rig()
        rig.answers["server"] = "http://vault.example"
        #expect(throws: SetupError.invalid(field: "server")) { _ = try SetupFlow.run(rig.steps()) }
        #expect(!rig.log.contains("approve") && !rig.log.contains("install") && !rig.log.contains("save"))
    }

    @Test(arguments: [ApprovalDecision.denied, .timedOut])
    func aRefusedApprovalChangesNothing(decision: ApprovalDecision) {
        let rig = Rig()
        rig.decision = decision
        #expect(throws: SetupError.denied) { _ = try SetupFlow.run(rig.steps()) }
        #expect(rig.log.last == "approve", "nothing may run after a refusal: \(rig.log)")
    }

    @Test func noWayToAskAHumanSaysWhyAndChangesNothing() {
        let rig = Rig()
        rig.decision = .unavailable(reason: "no Touch ID")
        #expect(throws: SetupError.approvalUnavailable(reason: "no Touch ID")) { _ = try SetupFlow.run(rig.steps()) }
        #expect(rig.log.last == "approve")
    }

    @Test func aGateRefusalStopsTheFlow() {
        let rig = Rig()
        rig.failAt = "approve"
        rig.failure = GateRefusal.lockedOut(secondsLeft: 30)
        #expect(throws: GateRefusal.lockedOut(secondsLeft: 30)) { _ = try SetupFlow.run(rig.steps()) }
        #expect(rig.log.last == "approve")
    }

    private struct StepFailure: Error, Equatable { let step: String }

    @Test(arguments: ["install", "configure", "verify", "commit"])
    func aFailingStepSavesNothingIsNotAuditedAndDiscardsTheStagedProfile(step: String) {
        let rig = Rig()
        rig.failAt = step
        rig.failure = StepFailure(step: step)
        #expect(throws: StepFailure(step: step)) { _ = try SetupFlow.run(rig.steps()) }
        #expect(!rig.log.contains("save") && !rig.log.contains("audit"), "\(rig.log)")
        #expect(rig.log.last == "discard", "the staged profile must be dropped on every way out: \(rig.log)")
        if step != "commit" { #expect(!rig.log.contains("commit"), "the live profile is replaced only after verify: \(rig.log)") }
    }

    @Test func aFailingSaveIsNotAuditedAsDone() {
        let rig = Rig()
        rig.failAt = "save"
        rig.failure = StoreError.writeFailed(reason: "disk")
        #expect(throws: StoreError.writeFailed(reason: "disk")) { _ = try SetupFlow.run(rig.steps()) }
        #expect(!rig.log.contains("audit"))
        #expect(rig.log.last == "discard")
    }

    @Test func theStagedProfileIsDiscardedAfterASuccessToo() throws {
        let rig = Rig()
        _ = try SetupFlow.run(rig.steps())
        #expect(rig.log.last == "discard")
    }

    @Test func nothingIsStagedOrDiscardedBeforeApproval() {
        let rig = Rig()
        rig.decision = .denied
        _ = try? SetupFlow.run(rig.steps())
        #expect(!rig.log.contains("discard"))
    }

    @Test func cancellingAtAnyQuestionStopsTheFlow() {
        for question in ["ask:server", "ask:email", "password"] {
            let rig = Rig()
            rig.failAt = question
            rig.failure = SetupError.cancelled
            #expect(throws: SetupError.cancelled) { _ = try SetupFlow.run(rig.steps()) }
            #expect(!rig.log.contains("approve"), Comment(rawValue: question))
        }
    }

    @Test func theApprovalTextNamesTheNewValuesAndNeverThePassword() throws {
        let rig = Rig()
        _ = try SetupFlow.run(rig.steps())
        let text = try #require(rig.approvalTexts.first)
        #expect(text.contains("https://vault.example") && text.contains("me@example.test") && text.contains("org-1"))
        #expect(text.lowercased().contains("first setup"))
        #expect(!text.contains("KNOWN"))
    }

    @Test func anExistingItemIsShownAsTheOldValuesAndOffersItsValuesAsDefaults() throws {
        let rig = Rig()
        rig.existing = try oldConfig()
        _ = try SetupFlow.run(rig.steps())
        let text = try #require(rig.approvalTexts.first)
        #expect(text.contains("was: https://old.example"))
        #expect(rig.askedDefaults["server"] == .some("https://old.example"))
        #expect(rig.askedDefaults["email"] == .some("old@example.test"))
        #expect(rig.askedDefaults["organization"] == .some("org-old"))
        #expect(rig.askedDefaults["collections"] == .some("col-old"))
    }

    @Test func anEmptyAnswerKeepsTheOldValue() throws {
        let rig = Rig()
        rig.existing = try oldConfig()
        rig.answers = ["server": "", "email": "", "organization": "", "collections": ""]
        _ = try SetupFlow.run(rig.steps())
        let text = try #require(rig.approvalTexts.first)
        #expect(text.contains("server: https://old.example (unchanged)"))
    }

    @Test func theOldProxyAndCertificateSettingsSurviveASetupThatDoesNotAskForThem() throws {
        let rig = Rig()
        rig.existing = try ProtectedConfig(
            serverURL: URL(string: "https://old.example")!, accountEmail: "old@example.test", organizationID: "org-old",
            collectionIDs: ["col-old"], masterPassword: SecretBuffer(copying: Array("old-pass-1234".utf8)), bwPin: plannedPin,
            nodeExtraCACerts: "/etc/ssl/internal-ca.pem", httpsProxy: "http://proxy.example:3128")
        _ = try SetupFlow.run(rig.steps())
        let saved = try #require(rig.saved.first)
        #expect(saved.nodeExtraCACerts == "/etc/ssl/internal-ca.pem")
        #expect(saved.httpsProxy == "http://proxy.example:3128")
    }

    @Test func anUnreadableOldItemIsSaidToBeReplacedAndHasNoOldValues() throws {
        let rig = Rig()
        rig.existingError = StoreError.unreadable(reason: "the item belongs to another build")
        _ = try SetupFlow.run(rig.steps())
        let text = try #require(rig.approvalTexts.first)
        #expect(!text.lowercased().contains("first setup"), "an item exists; it must not be called a first setup")
        #expect(text.contains("cannot read") && text.contains("replaced"))
        #expect(rig.log.contains("save"))
    }

    @Test func theAuditEventIsASetupEventWithoutAnyValue() throws {
        let rig = Rig()
        _ = try SetupFlow.run(rig.steps())
        let event = try #require(rig.audits.first)
        #expect(event.event == .setup)
        #expect(!"\(event)".contains("KNOWN") && !"\(event)".contains("vault.example"))
    }

    @Test func anInstalledBwOtherThanTheApprovedOneIsRefused() {
        let rig = Rig()
        var steps = rig.steps()
        steps.install = { .signedRelease(teamID: "SOMEONEELSE", path: "/x/bw") }
        #expect(throws: SetupError.installFailed(reason: "the installed bw is not the one that was approved")) {
            _ = try SetupFlow.run(steps)
        }
        #expect(!rig.log.contains("configure") && !rig.log.contains("save"))
    }
}

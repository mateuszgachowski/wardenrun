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
    var decision: ApprovalDecision = .approved
    private let lock = NSLock()
    private var _texts: [String] = []
    var texts: [String] { lock.lock(); defer { lock.unlock() }; return _texts }
    func approve(reason: String, timeout: TimeInterval) -> ApprovalDecision {
        lock.lock(); _texts.append(reason); lock.unlock()
        return decision
    }
}

private struct FixedInspector: ProcessInspector {
    func parentChain(of pid: Int32) -> [ProcessRecord] { [ProcessRecord(pid: 100, path: "/bin/zsh"), ProcessRecord(pid: 99, path: "/usr/bin/claude")] }
}

private struct NoSignature: BwSignatureChecker {
    func check(path: String, teamID: String) throws {}
    func checkRunning(pid: Int32, teamID: String) throws {}
}

private struct CountingRandom: RandomSource {
    func fill(_ buffer: UnsafeMutableRawBufferPointer) throws { for index in 0..<buffer.count { buffer[index] = UInt8(index % 251) } }
}

private final class Lines: @unchecked Sendable {
    private let lock = NSLock()
    private var all: [String] = []
    func add(_ line: String) { lock.lock(); all.append(line); lock.unlock() }
    var values: [String] { lock.lock(); defer { lock.unlock() }; return all }
}

@Suite(.serialized)
struct NewCommandTests {
    private func withHome(_ body: (String) throws -> Void) throws {
        let path = NSTemporaryDirectory() + "wardenrun-test-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: path) }
        try body(path)
    }

    private func config() throws -> ProtectedConfig {
        try ProtectedConfig(serverURL: URL(string: "https://vault.example")!, accountEmail: "a@b.example",
                            organizationID: "org-1", collectionIDs: ["col-1"],
                            masterPassword: SecretBuffer(copying: Array("master-password-VALUE".utf8)),
                            bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: "/opt/bw"))
    }

    private let options = NewOptions(name: "deploy-token", username: "svc", uri: nil, env: "DEPLOY_TOKEN", length: 24, charset: .alnum)

    private func run(home: String, store: FakeStore, approver: FakeApprover, output: Lines, errors: Lines,
                     create: (@Sendable (ProtectedConfig, NewOptions, SecretBuffer) throws -> String)?) -> Int32 {
        NewCommand.run(options: options, environment: [:], paths: WardenrunPaths(home: home), store: store, approver: approver,
                       inspector: FixedInspector(), signature: NoSignature(), random: CountingRandom(), createOverride: create,
                       output: { output.add($0) }, errorOutput: { errors.add($0) })
    }

    @Test func notSetUpAsksNothing() throws {
        try withHome { home in
            let approver = FakeApprover(), output = Lines(), errors = Lines()
            let code = run(home: home, store: FakeStore(), approver: approver, output: output, errors: errors, create: nil)
            #expect(code == 1)
            #expect(approver.texts.isEmpty)
            #expect(output.values.isEmpty)
            #expect(errors.values.first?.contains("wardenrun setup") == true)
        }
    }

    @Test func anApprovedNewStoresThePasswordPrintsOneLineAndLogsNoValue() throws {
        try withHome { home in
            let store = FakeStore(); store.config = try config()
            let approver = FakeApprover(), output = Lines(), errors = Lines()
            let stored = Lines()
            let code = run(home: home, store: store, approver: approver, output: output, errors: errors) { _, options, password in
                #expect(options.name == "deploy-token")
                stored.add(password.withUnsafeBytes { String(decoding: $0, as: UTF8.self) })
                return "99999999-0000-0000-0000-000000000001"
            }
            #expect(code == 0)
            let password = try #require(stored.values.first)
            #expect(password.count == 24)
            #expect(output.values == ["created \"deploy-token\" (id 99999999-0000-0000-0000-000000000001) in col-1"])
            #expect(!output.values.joined().contains(password))
            let sheet = try #require(approver.texts.first)
            #expect(sheet.contains("create item \"deploy-token\" in collection col-1"))
            #expect(sheet.contains("stored as env:DEPLOY_TOKEN"))
            #expect(sheet.contains("(from claude)"))
            let raw = try String(contentsOfFile: WardenrunPaths(home: home).auditLog, encoding: .utf8)
            #expect(raw.contains("\"event\":\"new\""))
            #expect(raw.contains("\"tier\":\"test tier\""))
            for value in [password, "master-password-VALUE"] { #expect(!raw.contains(value)) }
            #expect(errors.values.isEmpty)
        }
    }

    @Test func aDeniedNewCreatesNothingAndIs77() throws {
        try withHome { home in
            let store = FakeStore(); store.config = try config()
            let approver = FakeApprover(); approver.decision = .denied
            let output = Lines(), errors = Lines(), created = Lines()
            let code = run(home: home, store: store, approver: approver, output: output, errors: errors) { _, _, _ in
                created.add("called"); return "x"
            }
            #expect(code == 77)
            #expect(created.values.isEmpty)
            #expect(output.values.isEmpty)
        }
    }

    @Test func anExistingNameFailsWithOneSentence() throws {
        try withHome { home in
            let store = FakeStore(); store.config = try config()
            let output = Lines(), errors = Lines()
            let code = run(home: home, store: store, approver: FakeApprover(), output: output, errors: errors) { _, _, _ in
                throw BwError.alreadyExists
            }
            #expect(code == 1)
            #expect(output.values.isEmpty)
            #expect(errors.values == ["wardenrun: an item with that name already exists"])
        }
    }
}
#endif

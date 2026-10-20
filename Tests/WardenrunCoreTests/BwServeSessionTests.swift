import Foundation
import Testing
@testable import WardenrunCore

final class FakeHandle: BwServeHandle, @unchecked Sendable {
    let descriptor: Int32
    let standardError: [UInt8]
    let terminated = Box(false)

    init(descriptor: Int32, standardError: [UInt8] = []) {
        self.descriptor = descriptor
        self.standardError = standardError
    }

    func terminate(grace: TimeInterval) { terminated.value = true }
}

/// A stand-in for `bw serve`: answers the vault-management endpoints on a socketpair, from a thread.
final class FakeServe: BwServeLauncher, @unchecked Sendable {
    struct Seen { let method: String; let target: String; let body: [UInt8] }

    static let emptyList = "{\"success\":true,\"data\":{\"object\":\"list\",\"data\":[]}}"
    let seenBox = Box<[Seen]>([])
    let handles = Box<[FakeHandle]>([])

    // Behaviour, set before the first request.
    var password = "correct horse"
    var statusValue = "locked"
    var listBody = FakeServe.emptyList
    var createdID = "new-item-id"
    var overrides: [String: String] = [:]     // "POST /sync" -> a raw reply, or "SILENT"
    var launchError: BwError?
    var standardError = ""
    var closeAtOnce = false

    var seen: [Seen] { seenBox.value }
    var log: [String] { seen.map { "\($0.method) \($0.target)" } }
    var handle: FakeHandle? { handles.value.last }

    func launch() throws -> BwServeHandle {
        if let launchError { throw launchError }
        let (client, server) = try SocketPair.make()
        let handle = FakeHandle(descriptor: client, standardError: Array(standardError.utf8))
        handles.value.append(handle)
        let behaviour = self
        Thread.detachNewThread {
            behaviour.serve(server)
            close(server)
        }
        return handle
    }

    private func reply(_ status: String, _ body: String) -> String {
        "HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
    }

    private func serve(_ fd: Int32) {
        if closeAtOnce { return }
        while let request = readRequest(fd) {
            let line = request.head.components(separatedBy: "\r\n")[0].split(separator: " ")
            let method = String(line[0]), target = String(line[1])
            seenBox.value.append(Seen(method: method, target: target, body: request.body))
            let path = String(target.prefix { $0 != "?" })
            if let override = overrides[method + " " + path] {
                if override == "SILENT" { drainUntilClosed(fd); return }
                writeAll(fd, override)
                continue
            }
            switch (method, path) {
            case ("GET", "/status"):
                writeAll(fd, reply("200 OK", "{\"success\":true,\"data\":{\"object\":\"template\",\"template\":{\"status\":\"\(statusValue)\"}}}"))
            case ("POST", "/unlock"):
                let sent = (try? JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])?["password"] as? String
                if sent == password {
                    writeAll(fd, reply("200 OK", "{\"success\":true,\"data\":{\"object\":\"message\",\"title\":\"unlocked\",\"raw\":\"SESSION-KEY-123\"}}"))
                } else {
                    writeAll(fd, reply("400 Bad Request", "{\"success\":false,\"message\":\"Invalid master password.\"}"))
                }
            case ("POST", "/sync"), ("POST", "/lock"):
                writeAll(fd, reply("200 OK", "{\"success\":true,\"data\":{\"object\":\"message\",\"title\":\"done\"}}"))
            case ("GET", "/list/object/items"):
                writeAll(fd, reply("200 OK", listBody))
            case ("POST", "/object/item"):
                writeAll(fd, reply("200 OK", "{\"success\":true,\"data\":{\"object\":\"item\",\"id\":\"\(createdID)\",\"login\":{\"password\":\"ECHOED-SECRET\"}}}"))
            default:
                writeAll(fd, reply("404 Not Found", "{\"success\":false,\"message\":\"no such route\"}"))
            }
        }
    }
}

struct BwServeSessionTests {
    private func secret(_ text: String) -> SecretBuffer { SecretBuffer(copying: Array(text.utf8)) }

    private func started(_ fake: FakeServe, timeouts: BwTimeouts = .default) throws -> BwServeSession {
        let session = BwServeSession(launcher: fake, timeouts: timeouts)
        try session.start()
        return session
    }

    private func fast(_ change: (inout BwTimeouts) -> Void) -> BwTimeouts {
        var timeouts = BwTimeouts.default
        change(&timeouts)
        return timeouts
    }

    // MARK: the normal run

    @Test func theHappyPathSendsStatusUnlockSyncListLockInThatOrder() throws {
        let fake = FakeServe()
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        try session.sync()
        let list = try session.listItems(organizationID: "org-1", collectionID: "col-1")
        #expect(list.status == 200)
        try session.lock()
        session.close()
        #expect(fake.log == ["GET /status", "POST /unlock", "POST /sync",
                             "GET /list/object/items?organizationId=org-1&collectionId=col-1", "POST /lock"])
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func theUnlockBodyIsExactlyTheEncodedPassword() throws {
        let fake = FakeServe()
        fake.password = "p\"w\\d\n\u{1}é😀"
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        let expected = try SecretJSON.encode(.object([("password", .secret(secret(fake.password)))]))
        #expect(fake.seen.first { $0.target == "/unlock" }?.body == expected.withUnsafeBytes { Array($0) })
        session.close()
    }

    @Test func nothingButTheUnlockBodyEverCarriesThePassword() throws {
        let fake = FakeServe()
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        try session.sync()
        _ = try session.listItems(organizationID: "o", collectionID: "c")
        try session.lock()
        session.close()
        for request in fake.seen where request.target != "/unlock" {
            #expect(!String(decoding: request.body, as: UTF8.self).contains(fake.password))
            #expect(!request.target.contains("horse"))
        }
    }

    @Test func createItemReturnsTheReplyAndAnErrorStatusIsAServerError() throws {
        let fake = FakeServe()
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        let response = try session.createItem(secret("{\"name\":\"x\"}"))
        #expect(response.status == 200)
        #expect(fake.seen.last?.method == "POST" && fake.seen.last?.target == "/object/item")
        #expect(fake.seen.last?.body == Array("{\"name\":\"x\"}".utf8))
        response.wipe()

        fake.overrides["POST /object/item"] = "HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}"
        #expect(throws: BwError.serverError(status: 500)) { _ = try session.createItem(secret("{}")) }
        session.close()
    }

    @Test func queryValuesArePercentEncoded() throws {
        let fake = FakeServe()
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        _ = try session.listItems(organizationID: "a&b=c d", collectionID: "\u{e9}/1~-._")
        #expect(fake.seen.last?.target == "/list/object/items?organizationId=a%26b%3Dc%20d&collectionId=%C3%A9%2F1~-._")
        session.close()
    }

    // MARK: failures

    @Test func aWrongPasswordGivesUnlockFailedAndNoLockIsSentBecauseNothingWasUnlocked() throws {
        let fake = FakeServe()
        let session = try started(fake)
        #expect(throws: BwError.unlockFailed(message: "Invalid master password.")) {
            try session.unlock(password: secret("not the password"))
        }
        session.close()
        #expect(!fake.log.contains("POST /lock"))
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func aServerMessageThatEchoesThePasswordIsMasked() throws {
        let fake = FakeServe()
        let entered = "hunter2-hunter2"
        let echoed = "{\"success\":false,\"message\":\"bad password \(entered) given\"}"
        fake.overrides["POST /unlock"] = "HTTP/1.1 400 Bad\r\nContent-Length: \(echoed.utf8.count)\r\n\r\n" + echoed
        let session = try started(fake)
        do {
            try session.unlock(password: secret(entered))
            Issue.record("unlock succeeded")
        } catch let error as BwError {
            #expect(error == .unlockFailed(message: "bad password [REDACTED:master-password] given"))
            #expect(!String(describing: error).contains(entered))
        }
        session.close()
    }

    @Test func aMessageThatIsLongOrNotPlainASCIIIsReplacedByAFixedText() throws {
        for message in [String(repeating: "x", count: 201), "line\\nbreak", "caf\u{e9}"] {
            let fake = FakeServe()
            let body = "{\"success\":false,\"message\":\"\(message)\"}"
            fake.overrides["POST /unlock"] = "HTTP/1.1 400 Bad\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body
            let session = try started(fake)
            #expect(throws: BwError.unlockFailed(message: "unlock failed"), "\(message.debugDescription)") {
                try session.unlock(password: secret("whatever-it-is"))
            }
            session.close()
        }
    }

    @Test func aReplyThatIsNotJSONIsAServerErrorWithoutItsContent() throws {
        let fake = FakeServe()
        fake.overrides["POST /unlock"] = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 9\r\n\r\nSECRET123"
        let session = try started(fake)
        do {
            try session.unlock(password: secret("whatever-it-is"))
            Issue.record("unlock succeeded")
        } catch {
            #expect(error as? BwError == .serverError(status: 502))
            #expect(!String(describing: error).contains("SECRET123"))
        }
        session.close()
    }

    @Test func aFailedListStillSendsLockOnCloseAndTerminatesTheChild() throws {
        let fake = FakeServe()
        fake.overrides["GET /list/object/items"] = "HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}"
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        try session.sync()
        #expect(throws: BwError.serverError(status: 500)) { _ = try session.listItems(organizationID: "o", collectionID: "c") }
        session.close()
        #expect(fake.log.last == "POST /lock")
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func aLockThatFailsOnCloseIsSwallowedAndTheChildIsStillTerminated() throws {
        let fake = FakeServe()
        fake.overrides["POST /lock"] = "HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}"
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        session.close()
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func aServerThatNeverAnswersTimesOutWithThePhaseAndIsTerminated() throws {
        let fake = FakeServe()
        fake.overrides["POST /sync"] = "SILENT"
        let session = try started(fake, timeouts: fast { $0.request = 0.3 })
        try session.unlock(password: secret(fake.password))
        let start = Date()
        #expect(throws: BwError.timeout(phase: "sync")) { try session.sync() }
        session.close()
        #expect(Date().timeIntervalSince(start) < 3)
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func unlockUsesItsOwnTimeout() throws {
        let fake = FakeServe()
        fake.overrides["POST /unlock"] = "SILENT"
        let session = try started(fake, timeouts: fast { $0.unlock = 0.3; $0.request = 30 })
        let start = Date()
        #expect(throws: BwError.timeout(phase: "unlock")) { try session.unlock(password: secret(fake.password)) }
        #expect(Date().timeIntervalSince(start) < 3)
        session.close()
    }

    @Test func cancelDuringARequestThrowsCancelledAndCloseTerminates() throws {
        let fake = FakeServe()
        fake.overrides["POST /sync"] = "SILENT"
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { session.cancel() }
        let start = Date()
        #expect(throws: BwError.cancelled) { try session.sync() }
        #expect(Date().timeIntervalSince(start) < 3)
        #expect(throws: BwError.cancelled) { try session.sync() }
        session.close()
        #expect(fake.handle?.terminated.value == true)
    }

    // MARK: lifecycle

    @Test func closeIsIdempotent() throws {
        let fake = FakeServe()
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        session.close()
        session.close()
        #expect(fake.log.filter { $0 == "POST /lock" }.count == 1)
    }

    @Test func droppingAnUnlockedSessionLocksAndTerminates() throws {
        let fake = FakeServe()
        do {
            let session = try started(fake)
            try session.unlock(password: secret(fake.password))
        }
        #expect(fake.log.last == "POST /lock")
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func callsBeforeStartAndAfterCloseAreRefused() throws {
        let fake = FakeServe()
        let session = BwServeSession(launcher: fake)
        #expect(throws: BwError.protocolError("session not started")) { try session.sync() }
        try session.start()
        session.close()
        #expect(throws: BwError.protocolError("session closed")) { try session.sync() }
        #expect(throws: BwError.protocolError("session closed")) { try session.start() }
    }

    @Test func aLaunchFailureSurfaces() {
        let fake = FakeServe()
        fake.launchError = .spawnFailed(errno: ENOENT)
        let session = BwServeSession(launcher: fake)
        #expect(throws: BwError.spawnFailed(errno: ENOENT)) { try session.start() }
    }

    // MARK: startup problems

    @Test func anUnauthenticatedProfileGivesNotLoggedIn() throws {
        let fake = FakeServe()
        fake.statusValue = "unauthenticated"
        let session = BwServeSession(launcher: fake)
        #expect(throws: BwError.notLoggedIn) { try session.start() }
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func aServeThatExitsBecauseNobodyIsLoggedInGivesNotLoggedIn() throws {
        let fake = FakeServe()
        fake.closeAtOnce = true
        fake.standardError = "You are not logged in."
        let session = BwServeSession(launcher: fake)
        #expect(throws: BwError.notLoggedIn) { try session.start() }
        #expect(fake.handle?.terminated.value == true)
    }

    @Test func aServeThatExitsForAnyOtherReasonIsAFixedProtocolError() throws {
        let fake = FakeServe()
        fake.closeAtOnce = true
        fake.standardError = "something with SECRET123 in it"
        let session = BwServeSession(launcher: fake)
        do {
            try session.start()
            Issue.record("start succeeded")
        } catch {
            #expect(error as? BwError == .protocolError("bw serve did not start"))
            #expect(!String(describing: error).contains("SECRET123"))
        }
    }

    @Test func aServeThatNeverBecomesReadyTimesOutAtStart() throws {
        let fake = FakeServe()
        fake.overrides["GET /status"] = "SILENT"
        let session = BwServeSession(launcher: fake, timeouts: fast { $0.start = 0.3 })
        let start = Date()
        #expect(throws: BwError.timeout(phase: "start")) { try session.start() }
        #expect(Date().timeIntervalSince(start) < 3)
        #expect(fake.handle?.terminated.value == true)
    }

    // MARK: memory

    @Test func theUnlockReplyHoldsASessionKeyAndIsWipedAfterTheStatusCheck() throws {
        let fake = FakeServe()
        let session = try started(fake)
        let observed = Box<[HTTPResponse]>([])
        session.responseObserver = { observed.value.append($0) }
        try session.unlock(password: secret(fake.password))
        try session.sync()
        #expect(observed.value.count == 2)
        #expect(observed.value.allSatisfy { $0.body.isWiped })
        session.close()
    }

    @Test func theListReplyIsLeftToTheCallerToWipe() throws {
        let fake = FakeServe()
        fake.listBody = "{\"success\":true,\"data\":{\"data\":[]}}"
        let session = try started(fake)
        try session.unlock(password: secret(fake.password))
        let list = try session.listItems(organizationID: "o", collectionID: "c")
        #expect(!list.body.isWiped && list.body.count > 0)
        list.wipe()
        session.close()
    }

    // MARK: the real launcher

    @Test func theProcessLauncherHandsTheSocketToTheChildAndPassesTheServeArguments() throws {
        let spec = BwLaunchSpec(executable: "/bin/sh",
                                leadingArguments: ["-c", "printf '%s ' \"$@\" >&3; exec sleep 30", "bw"],
                                pinnedDirectories: [])
        let launcher = BwProcessServeLauncher(spec: spec, environment: ["PATH": "/usr/bin:/bin"])
        let handle = try launcher.launch()
        defer { handle.terminate(grace: 0.5); close(handle.descriptor) }
        var buffer = [UInt8](repeating: 0, count: 128)
        var text = ""
        let deadline = Date().addingTimeInterval(5)
        while !text.hasSuffix("--nointeraction ") && Date() < deadline {
            let count = read(handle.descriptor, &buffer, buffer.count)
            if count <= 0 { break }
            text += String(decoding: buffer[0..<count], as: UTF8.self)
        }
        #expect(text == "serve --hostname fd+connected://3 --nointeraction ")
    }
}

import Foundation
import Testing
@testable import WardenrunCore

/// The other end of a socketpair, played by a thread that runs `script` on its descriptor.
private final class FakeServer: @unchecked Sendable {
    private let clientFD: Int32
    private let group = DispatchGroup()

    init(_ script: @escaping @Sendable (Int32) -> Void) throws {
        let (client, server) = try SocketPair.make()
        clientFD = client
        group.enter()
        Thread.detachNewThread { [group] in
            script(server)
            close(server)
            group.leave()
        }
    }

    /// Hands out a client, closes it afterwards and waits for the script to end.
    func run<R>(maxBody: Int = 1 << 20, _ body: (LocalHTTPClient) throws -> R) rethrows -> R {
        let client = LocalHTTPClient(descriptor: clientFD, maxBody: maxBody)
        defer {
            client.close()
            _ = group.wait(timeout: .now() + 10)
        }
        return try body(client)
    }
}

struct LocalHTTPTests {
    private func bodyText(_ response: HTTPResponse) -> String {
        response.body.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
    }

    // MARK: request bytes

    @Test func aRequestWithoutABodyIsExactlyTheExpectedText() throws {
        let seen = Box<String?>(nil)
        let server = try FakeServer { fd in
            seen.value = readRequest(fd)?.head
            writeAll(fd, okReply("{}"))
        }
        try server.run { client in _ = try client.send(method: "GET", path: "/status", body: nil, deadline: 5) }
        #expect(seen.value == "GET /status HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n")
    }

    @Test func aPostWithoutABodyAnnouncesAZeroLength() throws {
        let seen = Box<String?>(nil)
        let server = try FakeServer { fd in
            seen.value = readRequest(fd)?.head
            writeAll(fd, okReply("{}"))
        }
        try server.run { client in _ = try client.send(method: "POST", path: "/sync", body: nil, deadline: 5) }
        #expect(seen.value == "POST /sync HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Length: 0\r\n\r\n")
    }

    @Test func theBodyIsSentAfterTheHeadWithItsExactLength() throws {
        let seen = Box<(head: String, body: [UInt8])?>(nil)
        let server = try FakeServer { fd in
            seen.value = readRequest(fd)
            writeAll(fd, okReply("{}"))
        }
        let payload = SecretBuffer(copying: Array("{\"password\":\"x\"}".utf8))
        try server.run { client in _ = try client.send(method: "POST", path: "/unlock", body: payload, deadline: 5) }
        #expect(seen.value?.head == "POST /unlock HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n"
                + "Content-Type: application/json\r\nContent-Length: 16\r\n\r\n")
        #expect(seen.value?.body == Array("{\"password\":\"x\"}".utf8))
    }

    @Test func aOneMegabyteBodyArrivesWhole() throws {
        let seen = Box<Int>(0)
        let server = try FakeServer { fd in
            seen.value = readRequest(fd)?.body.count ?? -1
            writeAll(fd, okReply("{}"))
        }
        let payload = SecretBuffer(copying: [UInt8](repeating: 0x61, count: 1 << 20))
        try server.run(maxBody: 100) { client in _ = try client.send(method: "POST", path: "/object/item", body: payload, deadline: 10) }
        #expect(seen.value == 1 << 20)
    }

    @Test func badRequestTargetsAreRefusedBeforeAnythingIsSent() throws {
        let received = Box<Bool>(false)
        let server = try FakeServer { fd in
            var byte: UInt8 = 0
            if read(fd, &byte, 1) > 0 { received.value = true }
        }
        try server.run { client in
            for (method, path) in [("GET", "no-slash"), ("GET", "/a b"), ("GET", "/a\r\nX-Injected: 1"), ("GET", "/\u{e9}"),
                                   ("get", "/x"), ("GE T", "/x"), ("", "/x"), ("GET", "")] {
                #expect(throws: BwError.protocolError("invalid request target"), "\(method) \(path.debugDescription)") {
                    _ = try client.send(method: method, path: path, body: nil, deadline: 1)
                }
            }
        }
        #expect(!received.value)
    }

    // MARK: responses

    @Test func theStatusAndBodyAreReturned() throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, okReply("{\"success\":true}")) }
        try server.run { client in
            let response = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(response.status == 200)
            #expect(bodyText(response) == "{\"success\":true}")
        }
    }

    @Test func nonSuccessStatusesAreReturnedNotThrown() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd)
            writeAll(fd, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}")
        }
        try server.run { client in
            let reply1 = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(reply1.status == 500)
        }
    }

    @Test func aReplySplitIntoOneByteWritesIsAssembled() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd)
            for byte in Array(okReply("{\"a\":[1,2,3]}").utf8) { writeAll(fd, [byte]) }
        }
        try server.run { client in
            let reply2 = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(bodyText(reply2) == "{\"a\":[1,2,3]}")
        }
    }

    @Test func aBodyThatStartsInTheSameChunkAsTheHeadersIsNotLost() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd)
            writeAll(fd, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123")
            usleep(100_000)
            writeAll(fd, "456789")
        }
        try server.run { client in
            let reply3 = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(bodyText(reply3) == "0123456789")
        }
    }

    @Test func headerNamesAreCaseInsensitiveAndValuesTrimmed() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd)
            writeAll(fd, "HTTP/1.1 200 OK\r\ncontent-LENGTH:   3  \r\nX-Other: a:b\r\n\r\nabc")
        }
        try server.run { client in
            let reply4 = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(bodyText(reply4) == "abc")
        }
    }

    @Test func a204WithoutContentLengthHasAnEmptyBody() throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, "HTTP/1.1 204 No Content\r\n\r\n") }
        try server.run { client in
            let response = try client.send(method: "POST", path: "/lock", body: nil, deadline: 5)
            #expect(response.status == 204 && response.body.count == 0)
        }
    }

    @Test func aZeroLengthBodyIsFine() throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") }
        try server.run { client in
            let reply5 = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(reply5.body.count == 0)
        }
    }

    @Test func twoRequestsShareOneConnection() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd); writeAll(fd, okReply("first"))
            _ = readRequest(fd); writeAll(fd, okReply("second"))
        }
        try server.run { client in
            let reply6 = try client.send(method: "GET", path: "/1", body: nil, deadline: 5)
            #expect(bodyText(reply6) == "first")
            let reply7 = try client.send(method: "GET", path: "/2", body: nil, deadline: 5)
            #expect(bodyText(reply7) == "second")
        }
    }

    // MARK: refused replies

    private func expectProtocolError(_ reply: String, _ message: String, sourceLocation: SourceLocation = #_sourceLocation) throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, reply) }
        server.run { client in
            #expect(throws: BwError.protocolError(message), sourceLocation: sourceLocation) {
                _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            }
        }
    }

    @Test func aReplyWithoutContentLengthIsRefused() throws {
        try expectProtocolError("HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\nbody", "reply without Content-Length")
    }

    @Test func aChunkedReplyIsRefused() throws {
        try expectProtocolError("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
                                "chunked replies are not supported")
    }

    @Test func malformedLengthsAreRefused() throws {
        for value in ["-1", "+5", "5x", "", "0x10", "1e3", "99999999999999999999"] {
            try expectProtocolError("HTTP/1.1 200 OK\r\nContent-Length: \(value)\r\n\r\nabcde", "malformed reply")
        }
    }

    @Test func conflictingContentLengthsAreRefusedAndEqualOnesAccepted() throws {
        try expectProtocolError("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", "malformed reply")
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc") }
        try server.run { client in
            let reply8 = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(bodyText(reply8) == "abc")
        }
    }

    @Test func malformedStatusLinesAreRefused() throws {
        for line in ["HTTP/1.1 abc OK", "HTTP/2 200 OK", "garbage", "HTTP/1.1 99 X", "HTTP/1.1 700 X", "HTTP/1.1"] {
            try expectProtocolError(line + "\r\nContent-Length: 0\r\n\r\n", "malformed reply")
        }
    }

    @Test func informationalRepliesAreRefused() throws {
        try expectProtocolError("HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n", "unexpected informational reply")
    }

    @Test func extraBytesAfterTheBodyAreRefused() throws {
        try expectProtocolError("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", "unexpected extra bytes")
    }

    @Test func headersLargerThan16KBAreRefused() throws {
        let filler = String(repeating: "X-Pad: " + String(repeating: "a", count: 200) + "\r\n", count: 100)
        try expectProtocolError("HTTP/1.1 200 OK\r\n" + filler + "Content-Length: 0\r\n\r\n", "reply headers too large")
    }

    @Test func aDeclaredLengthOverTheCapIsRefusedWithoutAllocatingIt() throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n") }
        server.run { client in
            let start = Date()
            #expect(throws: BwError.outputTooLarge) { _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 5) }
            #expect(Date().timeIntervalSince(start) < 2)
        }
    }

    @Test func theCapIsInclusive() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd); writeAll(fd, okReply(String(repeating: "a", count: 100)))
            _ = readRequest(fd); writeAll(fd, okReply(String(repeating: "a", count: 101)))
        }
        server.run(maxBody: 100) { client in
            #expect((try? client.send(method: "GET", path: "/1", body: nil, deadline: 5).body.count) == 100)
            #expect(throws: BwError.outputTooLarge) { _ = try client.send(method: "GET", path: "/2", body: nil, deadline: 5) }
        }
    }

    @Test func aBodyCutShortByTheServerIsAProtocolError() throws {
        try expectProtocolError("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", "reply ended early")
    }

    // MARK: connection trouble

    @Test func aServerThatClosesWithoutAnswerIsAProtocolError() throws {
        let server = try FakeServer { fd in _ = readRequest(fd) }
        server.run { client in
            #expect(throws: BwError.protocolError("connection closed by server")) {
                _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            }
        }
    }

    @Test func afterAConnectionCloseReplyTheNextRequestFailsCleanly() throws {
        let server = try FakeServer { fd in
            _ = readRequest(fd)
            writeAll(fd, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
        }
        server.run { client in
            #expect((try? client.send(method: "GET", path: "/1", body: nil, deadline: 5).status) == 200)
            #expect(throws: BwError.protocolError("connection closed by server")) {
                _ = try client.send(method: "GET", path: "/2", body: nil, deadline: 5)
            }
        }
    }

    @Test func aSilentServerTimesOutWithinTheDeadline() throws {
        let server = try FakeServer { fd in drainUntilClosed(fd) }
        server.run { client in
            let start = Date()
            #expect(throws: BwError.timeout(phase: "request")) { _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 0.3) }
            let elapsed = Date().timeIntervalSince(start)
            #expect(elapsed >= 0.25 && elapsed < 2, "took \(elapsed) s")
        }
    }

    @Test func cancelUnblocksARequestThatIsWaitingForTheReply() throws {
        let server = try FakeServer { fd in drainUntilClosed(fd) }
        server.run { client in
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { client.cancel() }
            let start = Date()
            #expect(throws: BwError.cancelled) { _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 20) }
            #expect(Date().timeIntervalSince(start) < 3)
        }
    }

    @Test func aCancelledClientRefusesFurtherRequests() throws {
        let server = try FakeServer { fd in drainUntilClosed(fd) }
        server.run { client in
            client.cancel()
            #expect(throws: BwError.cancelled) { _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 5) }
        }
    }

    @Test func writingToAClosedSocketThrowsInsteadOfRaisingSIGPIPE() throws {
        let server = try FakeServer { _ in }   // closes at once
        usleep(100_000)
        let payload = SecretBuffer(copying: [UInt8](repeating: 0x61, count: 1 << 20))
        server.run { client in
            #expect(throws: BwError.protocolError("connection closed by server")) {
                _ = try client.send(method: "POST", path: "/x", body: payload, deadline: 5)
            }
        }
    }

    // MARK: no leaks

    @Test func errorTextsNeverContainReplyBytes() throws {
        let replies = [
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Leak: SECRET123\r\n\r\nSECRET123",           // extra bytes
            "SECRET123 garbage\r\nContent-Length: 0\r\n\r\n",                                       // status line
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: SECRET123\r\n\r\nSECRET123",                     // chunked-ish
            "HTTP/1.1 200 OK\r\nContent-Length: SECRET123\r\n\r\n",                                 // length
            "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nSECRET123",                               // short
            "HTTP/1.1 200 OK\r\nSECRET123\r\n\r\n",                                                 // header without colon
        ]
        for reply in replies {
            let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, reply) }
            server.run { client in
                do {
                    _ = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
                    Issue.record("accepted: \(reply.debugDescription)")
                } catch {
                    #expect(!String(describing: error).contains("SECRET123"), "\(error)")
                    #expect(!error.localizedDescription.contains("SECRET123"))
                }
            }
        }
    }

    @Test func responseWipeZeroesTheBody() throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, okReply("S3CRET-VALUE")) }
        try server.run { client in
            let response = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(response.body.count == 12)
            response.wipe()
            #expect(response.body.count == 0)
            #expect(response.body.storageForTesting.allSatisfy { $0 == 0 })
        }
    }

    @Test func theBodyBufferIsLockedLikeAnyOtherSecretBuffer() throws {
        let server = try FakeServer { fd in _ = readRequest(fd); writeAll(fd, okReply("abc")) }
        try server.run { client in
            let response = try client.send(method: "GET", path: "/x", body: nil, deadline: 5)
            #expect(response.body.isLocked == SecretBuffer(copying: [1]).isLocked)
        }
    }
}

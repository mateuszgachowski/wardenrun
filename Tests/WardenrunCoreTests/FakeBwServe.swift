import Foundation
@testable import WardenrunCore

// An in-process stand-in for `bw serve`, shared by the session and vault tests.

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
    var listByCollection: [String: String] = [:]   // collectionId -> body; others get `listBody`
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
                let collection = target.components(separatedBy: "collectionId=").dropFirst().first ?? ""
                writeAll(fd, reply("200 OK", listByCollection[collection] ?? listBody))
            case ("POST", "/object/item"):
                writeAll(fd, reply("200 OK", "{\"success\":true,\"data\":{\"object\":\"item\",\"id\":\"\(createdID)\",\"login\":{\"password\":\"ECHOED-SECRET\"}}}"))
            default:
                writeAll(fd, reply("404 Not Found", "{\"success\":false,\"message\":\"no such route\"}"))
            }
        }
    }
}

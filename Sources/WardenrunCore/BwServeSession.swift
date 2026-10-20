import Foundation

/// How long each step of a `bw serve` session may take, in seconds.
public struct BwTimeouts: Equatable, Sendable {
    /// From launch until `bw serve` answers its first request.
    public var start: TimeInterval = 15
    /// Unlocking derives a key from the master password; a large KDF setting takes a while.
    public var unlock: TimeInterval = 60
    /// Every other request.
    public var request: TimeInterval = 30
    /// Waiting for `bw.lock` while another wardenrun is using `bw`.
    public var lockWait: TimeInterval = 30
    /// Between SIGTERM and SIGKILL.
    public var grace: TimeInterval = 2

    public init() {}
    public static let `default` = BwTimeouts()
}

/// A running `bw serve`: the descriptor wardenrun's end of its socket, and a way to end it.
public protocol BwServeHandle: AnyObject {
    var descriptor: Int32 { get }
    /// Everything the process printed (stderr and stdout). Read only after the connection failed.
    var printed: [UInt8] { get }
    func terminate(grace: TimeInterval)
}

public protocol BwServeLauncher: Sendable {
    func launch() throws -> BwServeHandle
}

/// Starts the pinned `bw` as `bw serve` on one end of a socketpair. Nothing listens on the
/// network: the only client is the descriptor wardenrun keeps.
public struct BwProcessServeLauncher: BwServeLauncher {
    /// The child's end of the socket is descriptor 3. Settled by the spike (DESIGN §5.2.6).
    static let arguments = ["serve", "--hostname", "fd+connected://3", "--port", String(BwServeSession.port),
                            "--nointeraction"]

    let spec: BwLaunchSpec
    let environment: [String: String]

    public init(spec: BwLaunchSpec, environment: [String: String]) {
        self.spec = spec
        self.environment = environment
    }

    public func launch() throws -> BwServeHandle {
        let (ours, theirs) = try SocketPair.make()
        let child: BwChild
        do {
            child = try BwProcess.start(spec: spec, arguments: Self.arguments, environment: environment,
                                        inherit: [(parent: theirs, child: 3)])
        } catch {
            close(ours)
            close(theirs)
            throw error
        }
        close(theirs)
        return BwProcessServeHandle(child: child, descriptor: ours)
    }
}

final class BwProcessServeHandle: BwServeHandle, @unchecked Sendable {
    private let child: BwChild
    let descriptor: Int32

    init(child: BwChild, descriptor: Int32) {
        self.child = child
        self.descriptor = descriptor
    }

    var printed: [UInt8] {
        _ = child.waitForOutput(timeout: 1)
        return child.capturedStderr + child.capturedStdout
    }

    func terminate(grace: TimeInterval) { child.terminate(grace: grace) }
}

/// One `bw serve` from launch to exit: ready, unlock, sync, list, create, lock.
///
/// The session never holds a secret longer than a call: the unlock reply (it carries a session
/// key) is wiped as soon as its status is read, and the replies a caller receives are the
/// caller's to wipe. Errors carry fixed texts, never a byte of a reply.
///
/// Use from one thread. `cancel()` may be called from any thread; `close()` may be called more
/// than once and runs on deinit.
public final class BwServeSession: @unchecked Sendable {
    /// `bw serve` accepts a request only when `Host` is `localhost:<its port>` (8087 unless told
    /// otherwise). No port is opened for `fd+connected://`, but the check still runs.
    static let port = 8087
    static let hostHeader = "localhost:\(port)"

    private let launcher: BwServeLauncher
    private let timeouts: BwTimeouts
    private let state = NSLock()
    private var handle: BwServeHandle?
    private var client: LocalHTTPClient?
    private var started = false
    private var closed = false
    private var cancelled = false
    private var unlocked = false

    /// Test hook: sees every reply the session receives, before the session or its caller wipes it.
    var responseObserver: ((HTTPResponse) -> Void)?

    public init(launcher: BwServeLauncher, timeouts: BwTimeouts = .default) {
        self.launcher = launcher
        self.timeouts = timeouts
    }

    deinit { close() }

    // MARK: lifecycle

    /// Launches `bw serve` and waits until it answers. Throws `.notLoggedIn` when `bw` has no
    /// profile to unlock. On any failure the session is closed.
    public func start() throws {
        try state.withLock {
            if closed { throw BwError.protocolError("session closed") }
            if started { throw BwError.protocolError("session already started") }
            if cancelled { throw BwError.cancelled }
            started = true
        }
        let launched: BwServeHandle
        do {
            launched = try launcher.launch()
        } catch {
            close()
            throw error
        }
        let http = LocalHTTPClient(descriptor: launched.descriptor, host: Self.hostHeader)
        let raced = state.withLock { () -> Bool in
            handle = launched
            client = http
            return cancelled
        }
        // A cancel that came before the client existed.
        if raced { http.cancel() }

        do {
            let reply = try exchange("GET", "/status", body: nil, deadline: timeouts.start, phase: "start")
            defer { reply.wipe() }
            guard reply.status == 200 else { throw BwError.serverError(status: reply.status) }
            let status = reply.body.withUnsafeBytes { BwReply.templateStatus($0) }
            if status.map({ $0.elementsEqual("unauthenticated".utf8) }) == true { throw BwError.notLoggedIn }
            guard status.map({ $0.elementsEqual("locked".utf8) }) == true else {
                throw BwError.protocolError("unexpected bw status")
            }
        } catch {
            let mapped = explainStartFailure(error, launched)
            close()
            throw mapped
        }
    }

    /// The process is gone before it answered: `bw` says why on stderr, and "not logged in" is
    /// the one reason wardenrun acts on. Anything else is reported in fixed words.
    private func explainStartFailure(_ error: Error, _ launched: BwServeHandle) -> Error {
        guard case BwError.protocolError(let text) = error,
              text == "connection closed by server" || text == "reply ended early" else { return error }
        let said = String(decoding: launched.printed, as: UTF8.self).lowercased()
        if said.contains("not logged in") { return BwError.notLoggedIn }
        return BwError.protocolError("bw serve did not start")
    }

    /// Makes a blocked or coming call fail with `.cancelled`. Thread-safe.
    public func cancel() {
        let active = state.withLock { () -> LocalHTTPClient? in
            cancelled = true
            return client
        }
        active?.cancel()
    }

    /// Locks the vault if it is unlocked (best effort), closes the socket and ends `bw serve`.
    public func close() {
        let taken = state.withLock { () -> (BwServeHandle?, LocalHTTPClient?, Bool)? in
            if closed { return nil }
            closed = true
            let result = (handle, client, unlocked)
            handle = nil
            client = nil
            unlocked = false
            return result
        }
        guard let (handle, client, wasUnlocked) = taken else { return }
        if wasUnlocked, let client {
            // Best effort: the process is terminated next, which empties its memory anyway.
            if let reply = try? client.send(method: "POST", path: "/lock", body: nil,
                                            deadline: min(timeouts.request, 5)) {
                responseObserver?(reply)
                reply.wipe()
            }
        }
        client?.close()
        handle?.terminate(grace: timeouts.grace)
    }

    // MARK: requests

    public func unlock(password: SecretBuffer) throws {
        let body = try SecretJSON.encode(.object([("password", .secret(password))]))
        defer { body.wipe() }
        let reply = try exchange("POST", "/unlock", body: body, deadline: timeouts.unlock, phase: "unlock")
        defer { reply.wipe() }
        let success = reply.body.withUnsafeBytes { BwReply.success($0) }
        guard reply.status == 200, success == true else {
            throw unlockFailure(reply, password: password)
        }
        state.withLock { unlocked = true }
    }

    public func sync() throws {
        let reply = try exchange("POST", "/sync", body: nil, deadline: timeouts.request, phase: "sync")
        defer { reply.wipe() }
        try requireSuccess(reply)
    }

    /// The items of one collection. The caller wipes the reply.
    public func listItems(organizationID: String, collectionID: String) throws -> HTTPResponse {
        let path = "/list/object/items?organizationId=\(Self.percentEncode(organizationID))"
            + "&collectionId=\(Self.percentEncode(collectionID))"
        let reply = try exchange("GET", path, body: nil, deadline: timeouts.request, phase: "list")
        guard reply.status == 200 else {
            reply.wipe()
            throw BwError.serverError(status: reply.status)
        }
        return reply
    }

    /// Creates an item from a complete item JSON. The caller wipes the reply.
    public func createItem(_ body: SecretBuffer) throws -> HTTPResponse {
        let reply = try exchange("POST", "/object/item", body: body, deadline: timeouts.request, phase: "create")
        guard reply.status == 200 else {
            reply.wipe()
            throw BwError.serverError(status: reply.status)
        }
        return reply
    }

    public func lock() throws {
        let reply = try exchange("POST", "/lock", body: nil, deadline: timeouts.request, phase: "lock")
        defer { reply.wipe() }
        try requireSuccess(reply)
        state.withLock { unlocked = false }
    }

    // MARK: helpers

    private func exchange(_ method: String, _ path: String, body: SecretBuffer?,
                          deadline: TimeInterval, phase: String) throws -> HTTPResponse {
        let http = try state.withLock { () -> LocalHTTPClient in
            if closed { throw BwError.protocolError("session closed") }
            guard let client else { throw BwError.protocolError("session not started") }
            return client
        }
        do {
            let reply = try http.send(method: method, path: path, body: body, deadline: deadline)
            responseObserver?(reply)
            return reply
        } catch BwError.timeout(_) {
            throw BwError.timeout(phase: phase)
        }
    }

    private func requireSuccess(_ reply: HTTPResponse) throws {
        guard reply.status == 200 else { throw BwError.serverError(status: reply.status) }
        let success = reply.body.withUnsafeBytes { BwReply.success($0) }
        guard success == true else { throw BwError.protocolError("reply was not a success") }
    }

    /// A refused unlock is `.unlockFailed` with the server's words, if they are safe to show;
    /// anything else (a gateway error, a reply that is not JSON) is a server error.
    private func unlockFailure(_ reply: HTTPResponse, password: SecretBuffer) -> BwError {
        let clientError = (400..<500).contains(reply.status)
        let refused = reply.status == 200 || clientError
        var message = reply.body.withUnsafeBytes { BwReply.message($0) }
        defer { if message != nil { BwBytes.wipe(&message!) } }
        guard refused, message != nil || reply.status == 200 else { return .serverError(status: reply.status) }
        return .unlockFailed(message: Self.safeMessage(message, password: password))
    }

    private static let fixedUnlockMessage = "unlock failed"

    /// Printable ASCII, at most 200 characters, with the master password masked if the server
    /// echoed it. Anything else is replaced by a fixed text.
    private static func safeMessage(_ raw: [UInt8]?, password: SecretBuffer) -> String {
        guard let raw, raw.count <= 4096 else { return fixedUnlockMessage }
        var typed = password.withUnsafeBytes { Array($0) }
        defer { BwBytes.wipe(&typed) }
        let plan = MaskNeedles.plan(for: [MaskSecret(name: "master-password", value: typed)])
        // A password too short to mask could be echoed unmasked: say nothing of the message.
        guard plan.tooShort.isEmpty else { return fixedUnlockMessage }
        let masked = StreamMasker.maskAll(raw, needles: plan.needles)
        guard masked.count <= 200, masked.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }) else { return fixedUnlockMessage }
        return String(decoding: masked, as: UTF8.self)
    }

    /// Unreserved characters stay; every other byte of the UTF-8 form becomes `%XX`.
    static func percentEncode(_ text: String) -> String {
        let hex = Array("0123456789ABCDEF".utf8)
        var out = [UInt8]()
        for byte in text.utf8 {
            switch byte {
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2D, 0x2E, 0x5F, 0x7E:
                out.append(byte)
            default:
                out += [0x25, hex[Int(byte >> 4)], hex[Int(byte & 0x0F)]]
            }
        }
        return String(decoding: out, as: UTF8.self)
    }
}

enum BwBytes {
    static func wipe(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            #if canImport(Darwin)
            _ = memset_s(base, raw.count, 0, raw.count)
            #else
            explicit_bzero(base, raw.count)
            #endif
        }
    }
}

/// The few fields of `bw serve` replies that the session itself reads (INFERRED shapes, to be
/// confirmed by the spike). Anything that does not fit comes back as `nil`.
enum BwReply {
    /// Top-level `success`.
    static func success(_ body: UnsafeRawBufferPointer) -> Bool? {
        var found: Bool?
        guard scan(body, { key, value in
            if isKey(key, "success"), try value.kind() == .bool { found = try value.bool() } else { try value.skipValue() }
        }) else { return nil }
        return found
    }

    /// Top-level `message`, a string.
    static func message(_ body: UnsafeRawBufferPointer) -> [UInt8]? {
        var found: [UInt8]?
        guard scan(body, { key, value in
            if isKey(key, "message"), try value.kind() == .string { found = try value.string() } else { try value.skipValue() }
        }) else { return nil }
        return found
    }

    /// `data.template.status` of the `/status` reply.
    static func templateStatus(_ body: UnsafeRawBufferPointer) -> [UInt8]? {
        var found: [UInt8]?
        guard scan(body, { key, value in
            guard isKey(key, "data"), try value.kind() == .object else { try value.skipValue(); return }
            try value.members { dataKey, dataValue in
                guard isKey(dataKey, "template"), try dataValue.kind() == .object else { try dataValue.skipValue(); return }
                try dataValue.members { templateKey, templateValue in
                    if isKey(templateKey, "status"), try templateValue.kind() == .string {
                        found = try templateValue.string()
                    } else {
                        try templateValue.skipValue()
                    }
                }
            }
        }) else { return nil }
        return found
    }

    /// `data.id` of an item reply, if it is a plausible id: 1 to 64 letters, digits and hyphens.
    /// The id is printed to the user later, so nothing else is let through.
    static func createdID(_ body: UnsafeRawBufferPointer) -> String? {
        var found: [UInt8]?
        guard scan(body, { key, value in
            guard isKey(key, "data"), try value.kind() == .object else { try value.skipValue(); return }
            try value.members { dataKey, dataValue in
                if isKey(dataKey, "id"), try dataValue.kind() == .string {
                    found = try dataValue.string()
                } else {
                    try dataValue.skipValue()
                }
            }
        }), let found, (1...64).contains(found.count), found.allSatisfy({
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D
        }) else { return nil }
        return String(decoding: found, as: UTF8.self)
    }

    private static func scan(_ body: UnsafeRawBufferPointer,
                             _ member: (_ key: [UInt8], _ value: inout JSONCursor) throws -> Void) -> Bool {
        var cursor = JSONCursor(body)
        do {
            guard try cursor.kind() == .object else { return false }
            try cursor.members(member)
            try cursor.finish()
            return true
        } catch {
            return false
        }
    }
}

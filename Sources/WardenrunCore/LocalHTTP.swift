import Foundation

/// A reply from `bw serve`. The body sits in locked memory, exactly as long as the server said.
public final class HTTPResponse: @unchecked Sendable {
    public let status: Int
    public let body: SecretBuffer

    init(status: Int, body: SecretBuffer) {
        self.status = status
        self.body = body
    }

    public func wipe() { body.wipe() }
}

/// A small HTTP/1.1 client for one private socket (`bw serve` on an inherited socketpair).
///
/// It speaks only what that server needs and refuses the rest: a reply must carry
/// `Content-Length` (chunked replies are refused), headers are capped at 16 KB, and the body is
/// capped at `maxBody` and read into one exact-size locked allocation, never into a growing
/// array. Errors say what went wrong in fixed words and never quote a byte of the reply,
/// which may hold secrets.
public final class LocalHTTPClient: @unchecked Sendable {
    private static let headerLimit = 16 * 1024
    private static let headerBuffer = 20 * 1024

    private let descriptor: Int32
    private let maxBody: Int
    private let host: String
    private let state = NSLock()
    private var cancelled = false
    private var closed = false
    private var broken = false

    /// `host` is what the `Host` header says. `bw serve` refuses any value but its own
    /// `localhost:<port>` forms (DNS-rebinding guard), so the caller passes the port it started it with.
    public init(descriptor: Int32, maxBody: Int = 32 << 20, host: String = "localhost") {
        self.descriptor = descriptor
        self.maxBody = maxBody
        self.host = host
        // Non-blocking, so that a peer that stops reading cannot hold a write past the deadline.
        let flags = fcntl(descriptor, F_GETFL)
        if flags >= 0 { _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) }
    }

    deinit { close() }

    /// Makes a request that is blocked, or comes next, fail with `.cancelled`. Thread-safe.
    public func cancel() {
        state.lock(); defer { state.unlock() }
        cancelled = true
        if !closed { shutdown(descriptor, Int32(SHUT_RDWR)) }
    }

    public func close() {
        state.lock(); defer { state.unlock() }
        guard !closed else { return }
        closed = true
        Foundation.close(descriptor)
    }

    private var isCancelled: Bool { state.lock(); defer { state.unlock() }; return cancelled }

    /// `deadline` is the number of seconds the whole exchange may take.
    public func send(method: String, path: String, body: SecretBuffer?, deadline: TimeInterval) throws -> HTTPResponse {
        guard Self.isValidMethod(method), Self.isValidTarget(path) else { throw BwError.protocolError("invalid request target") }
        if isCancelled { throw BwError.cancelled }
        state.lock()
        let unusable = broken || closed
        state.unlock()
        if unusable { throw BwError.protocolError("connection closed by server") }

        let limit = Date().addingTimeInterval(deadline)
        do {
            try writeRequest(method: method, path: path, body: body, limit: limit)
            return try readResponse(limit: limit)
        } catch {
            state.lock(); broken = true; state.unlock()
            throw error
        }
    }

    // MARK: request

    private static func isValidMethod(_ method: String) -> Bool {
        !method.isEmpty && method.utf8.allSatisfy { $0 >= 0x41 && $0 <= 0x5A }
    }

    /// Visible ASCII, starts with `/`. Callers percent-encode what they put in a query.
    private static func isValidTarget(_ path: String) -> Bool {
        path.hasPrefix("/") && path.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F }
    }

    private func writeRequest(method: String, path: String, body: SecretBuffer?, limit: Date) throws {
        var head = "\(method) \(path) HTTP/1.1\r\nHost: \(host)\r\nAccept: application/json\r\n"
        if let body {
            head += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n"
        } else if method != "GET" && method != "HEAD" {
            head += "Content-Length: 0\r\n"
        }
        head += "\r\n"
        let headBytes = Array(head.utf8)
        try headBytes.withUnsafeBytes { try sendAll($0, limit: limit) }
        if let body, body.count > 0 {
            // From the buffer itself: the secret is never copied behind the head.
            try body.withUnsafeBytes { try sendAll($0, limit: limit) }
        }
    }

    private func sendAll(_ bytes: UnsafeRawBufferPointer, limit: Date) throws {
        guard let base = bytes.baseAddress else { return }
        var sent = 0
        while sent < bytes.count {
            try waitReady(events: Int16(POLLOUT), limit: limit)
            let count = SocketPair.send(descriptor, base + sent, bytes.count - sent)
            if count > 0 {
                sent += count
            } else if count < 0 && (errno == EINTR || errno == EAGAIN) {
                continue
            } else {
                if isCancelled { throw BwError.cancelled }
                throw BwError.protocolError("connection closed by server")
            }
        }
    }

    // MARK: reply

    private func readResponse(limit: Date) throws -> HTTPResponse {
        let capacity = Self.headerBuffer
        var head = [UInt8](repeating: 0, count: capacity)
        defer { Self.wipe(&head) }
        var filled = 0
        var headerEnd: Int?
        while headerEnd == nil {
            guard filled < capacity else { throw BwError.protocolError("reply headers too large") }
            let count = try head.withUnsafeMutableBytes { try readSome($0.baseAddress! + filled, capacity - filled, limit: limit) }
            if count == 0 { throw BwError.protocolError("connection closed by server") }
            filled += count
            headerEnd = Self.findHeaderEnd(head, filled)
        }
        let end = headerEnd!
        guard end + 4 <= Self.headerLimit else { throw BwError.protocolError("reply headers too large") }

        let parsed = try Self.parseHead(Array(head[0..<end]))
        guard parsed.length <= maxBody else { throw BwError.outputTooLarge }
        let leftover = filled - (end + 4)
        guard leftover <= parsed.length else { throw BwError.protocolError("unexpected extra bytes") }

        let body = try SecretBuffer(count: parsed.length) { raw in
            guard let base = raw.baseAddress else { return }
            head.withUnsafeBytes { _ = memcpy(base, $0.baseAddress! + end + 4, leftover) }
            var got = leftover
            while got < raw.count {
                let count = try readSome(base + got, raw.count - got, limit: limit)
                if count == 0 { throw BwError.protocolError("reply ended early") }
                got += count
            }
        }
        if !parsed.keepAlive { state.lock(); broken = true; state.unlock() }
        return HTTPResponse(status: parsed.status, body: body)
    }

    private static func findHeaderEnd(_ bytes: [UInt8], _ filled: Int) -> Int? {
        guard filled >= 4 else { return nil }
        for index in 0...(filled - 4)
        where bytes[index] == 13 && bytes[index + 1] == 10 && bytes[index + 2] == 13 && bytes[index + 3] == 10 {
            return index
        }
        return nil
    }

    private struct Head { var status: Int; var length: Int; var keepAlive: Bool }

    private static func parseHead(_ bytes: [UInt8]) throws -> Head {
        let malformed = BwError.protocolError("malformed reply")
        let lines = String(decoding: bytes, as: UTF8.self).components(separatedBy: "\r\n")
        let parts = lines[0].split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, parts[0] == "HTTP/1.1" || parts[0] == "HTTP/1.0", parts[1].utf8.count == 3,
              let status = Int(parts[1]), (100...599).contains(status) else { throw malformed }

        var length: Int?
        var keepAlive = parts[0] == "HTTP/1.1"
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else { throw malformed }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
            switch name {
            case "content-length":
                guard !value.isEmpty, value.utf8.count <= 10, value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                      let number = Int(value) else { throw malformed }
                if let length, length != number { throw malformed }
                length = number
            case "transfer-encoding":
                throw BwError.protocolError("chunked replies are not supported")
            case "connection":
                let tokens = value.lowercased().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                if tokens.contains("close") { keepAlive = false }
            default:
                break
            }
        }
        if status < 200 { throw BwError.protocolError("unexpected informational reply") }
        if length == nil, status == 204 || status == 304 { length = 0 }
        guard let known = length else { throw BwError.protocolError("reply without Content-Length") }
        return Head(status: status, length: known, keepAlive: keepAlive)
    }

    // MARK: waiting

    private func waitReady(events: Int16, limit: Date) throws {
        while true {
            if isCancelled { throw BwError.cancelled }
            let remaining = limit.timeIntervalSinceNow
            if remaining <= 0 { throw BwError.timeout(phase: "request") }
            var descriptorState = pollfd(fd: descriptor, events: events, revents: 0)
            // Wake up now and then, so a cancel that arrives between two polls is noticed.
            let milliseconds = Int32(min(remaining * 1000, 250).rounded(.up))
            let result = poll(&descriptorState, 1, milliseconds)
            if result > 0 { return }
            if result < 0 && errno != EINTR { throw BwError.protocolError("connection closed by server") }
        }
    }

    /// Reads at most `count` bytes into `pointer`; 0 means the peer closed.
    private func readSome(_ pointer: UnsafeMutableRawPointer, _ count: Int, limit: Date) throws -> Int {
        while true {
            try waitReady(events: Int16(POLLIN), limit: limit)
            let result = read(descriptor, pointer, count)
            if result > 0 { return result }
            if result < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            // End of stream, or ECONNRESET and friends: the peer is gone, unless we shut it down ourselves.
            if isCancelled { throw BwError.cancelled }
            return 0
        }
    }

    private static func wipe(_ bytes: inout [UInt8]) {
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

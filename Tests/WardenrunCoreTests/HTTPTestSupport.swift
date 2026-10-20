import Foundation
@testable import WardenrunCore

// Helpers shared by the tests that play an HTTP server on one end of a socketpair.

final class Box<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ value: T) { stored = value }
    var value: T {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}

func readUntilHeadersEnd(_ fd: Int32) -> [UInt8]? {
    var data: [UInt8] = []
    var byte: UInt8 = 0
    while !data.suffix(4).elementsEqual([13, 10, 13, 10]) {
        if read(fd, &byte, 1) <= 0 { return nil }
        data.append(byte)
    }
    return data
}

func readRequest(_ fd: Int32) -> (head: String, body: [UInt8])? {
    guard let head = readUntilHeadersEnd(fd) else { return nil }
    let text = String(decoding: head, as: UTF8.self)
    var length = 0
    for line in text.components(separatedBy: "\r\n") where line.lowercased().hasPrefix("content-length:") {
        length = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) ?? 0
    }
    var body = [UInt8](repeating: 0, count: length)
    var got = 0
    while got < length {
        let n = body.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, length - got) }
        if n <= 0 { return nil }
        got += n
    }
    return (text, body)
}

func writeAll(_ fd: Int32, _ text: String) { writeAll(fd, Array(text.utf8)) }

func writeAll(_ fd: Int32, _ bytes: [UInt8]) {
    var sent = 0
    while sent < bytes.count {
        let n = bytes.withUnsafeBytes { SocketPair.send(fd, $0.baseAddress! + sent, bytes.count - sent) }
        if n <= 0 { return }
        sent += n
    }
}

func drainUntilClosed(_ fd: Int32) {
    var byte: UInt8 = 0
    while read(fd, &byte, 1) > 0 {}
}

func okReply(_ body: String) -> String {
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body
}


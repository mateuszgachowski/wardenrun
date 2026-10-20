#if canImport(Darwin)
import Darwin
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

/// A pseudo-terminal pair: what the test types goes into `master`, the code under test reads `slave`.
private final class Pty {
    let master: Int32
    let slave: Int32

    init() throws {
        var master: Int32 = -1, slave: Int32 = -1
        try #require(openpty(&master, &slave, nil, nil, nil) == 0)
        self.master = master
        self.slave = slave
        deadManSwitch()
    }

    deinit {
        closeMaster()
        if slave >= 0 { close(slave) }
    }

    func type(_ bytes: [UInt8]) { _ = bytes.withUnsafeBytes { write(master, $0.baseAddress, $0.count) } }

    private let masterLock = NSLock()
    private var masterClosed = false

    func closeMaster() {
        masterLock.lock(); defer { masterLock.unlock() }
        if !masterClosed { close(master); masterClosed = true }
    }

    /// Types `bytes` as soon as the code under test has switched the terminal to no-echo, as a
    /// person would after seeing the prompt. Bytes typed earlier would meet the terminal driver's
    /// own echo and line editing (and Ctrl-C would never arrive as a byte). A dead-man switch ends
    /// a read that nobody answers, so that a failing test fails instead of hanging.
    func typeWhenReady(_ bytes: [UInt8], thenCloseMaster: Bool = false) {
        Thread.detachNewThread { [self] in
            let deadline = Date().addingTimeInterval(10)
            while flags() & tcflag_t(ECHO) != 0 && Date() < deadline { usleep(2_000) }
            if !bytes.isEmpty { type(bytes) }
            if thenCloseMaster { usleep(50_000); closeMaster() }
        }
    }

    func deadManSwitch(after seconds: TimeInterval = 15) {
        Thread.detachNewThread { [self] in
            sleep(UInt32(seconds))
            closeMaster()
        }
    }

    /// The local-mode flags without PENDIN, which the kernel sets by itself when the mode changes
    /// while input is waiting; it is not a setting of ours.
    func flags() -> tcflag_t {
        var t = termios()
        tcgetattr(slave, &t)
        return t.c_lflag & ~tcflag_t(0x2000_0000)
    }

    func readEcho() -> String {
        // What the terminal would have shown: everything written to the slave side is readable on master.
        var buffer = [UInt8](repeating: 0, count: 4096)
        var flagsNow = fcntl(master, F_GETFL)
        flagsNow |= O_NONBLOCK
        _ = fcntl(master, F_SETFL, flagsNow)
        let count = read(master, &buffer, buffer.count)
        return String(decoding: buffer[0..<max(count, 0)], as: UTF8.self)
    }
}

private func text(_ buffer: SecretBuffer) -> String { buffer.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }

struct TerminalTests {
    @Test func hiddenReadReturnsTheTypedBytesWithoutTheNewlineFromAPty() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array("pa55 w0rd ł\n".utf8))
        let secret = try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "Password: ")
        #expect(text(secret) == "pa55 w0rd ł")
    }

    @Test func thePromptIsShownAndTheTypedBytesAreNeverEchoed() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array("topsecret\n".utf8))
        _ = try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "Master password: ")
        let shown = pty.readEcho()
        #expect(shown.contains("Master password: "))
        #expect(!shown.contains("topsecret"))
    }

    @Test func backspaceRemovesTheLastCharacterIncludingAMultiByteOne() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array("abć".utf8) + [0x7F] + Array("d\n".utf8))
        #expect(text(try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "")) == "abd")
    }

    @Test func arrowKeysAndOtherEscapeSequencesAreNotPartOfThePassword() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array("ab".utf8) + [0x1B, 0x5B, 0x41] + Array("c\n".utf8))
        #expect(text(try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "")) == "abc")
    }

    @Test func termiosIsRestoredAfterSuccessEOFAndErrors() throws {
        let pty = try Pty()
        let original = pty.flags()
        pty.typeWhenReady(Array("ok\n".utf8))
        _ = try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "")
        #expect(pty.flags() == original)

        pty.typeWhenReady([0x03])   // Ctrl-C
        #expect(throws: TerminalError.cancelled) { try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "") }
        #expect(pty.flags() == original)

        pty.typeWhenReady(Array(repeating: UInt8(ascii: "a"), count: 1025) + [0x0A])
        #expect(throws: TerminalError.tooLong) { try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "") }
        #expect(pty.flags() == original)

        pty.typeWhenReady([], thenCloseMaster: true)   // EOF / hang-up while reading
        #expect(throws: TerminalError.endOfInput) { try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "") }
        #expect(pty.flags() == original)
    }

    @Test func aRefusedNonTTYThrows() throws {
        var fds: [Int32] = [0, 0]
        try #require(pipe(&fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        _ = Array("secret\n".utf8).withUnsafeBytes { write(fds[1], $0.baseAddress, $0.count) }
        #expect(throws: TerminalError.notInteractive) { try Terminal.readHidden(from: fds[0], to: fds[1], prompt: "") }
    }

    @Test func overlongInputIsRejectedAt1024Bytes() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array(repeating: UInt8(ascii: "x"), count: 1024) + [0x0A])
        #expect(text(try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "")).count == 1024)
        pty.typeWhenReady(Array(repeating: UInt8(ascii: "x"), count: 1025) + [0x0A])
        #expect(throws: TerminalError.tooLong) { try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "") }
    }

    @Test func theRestOfAnOverlongLineIsThrownAwayNotLeftForTheShell() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array(repeating: UInt8(ascii: "a"), count: 1030) + Array("TAIL\n".utf8))
        #expect(throws: TerminalError.tooLong) { try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "") }
        usleep(200_000)   // the rest of the line has been typed by now
        var pending: Int32 = 0
        ioctl(pty.slave, 0x4004_667F, &pending)   // FIONREAD
        #expect(pending == 0, "\(pending) typed bytes are still queued for whoever reads the terminal next")
    }

    @Test func theBufferIsWipedWhenReadingFails() throws {
        let pty = try Pty()
        pty.typeWhenReady(Array("part".utf8) + [0x03])
        var staging: SecretBuffer?
        #expect(throws: TerminalError.cancelled) {
            try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "", onStagingBuffer: { staging = $0 })
        }
        let buffer = try #require(staging)
        #expect(buffer.isWiped)
    }

    @Test func anEmptyLineIsAnEmptyPasswordNotAnError() throws {
        let pty = try Pty()
        pty.typeWhenReady([0x0A])
        #expect(try Terminal.readHidden(from: pty.slave, to: pty.slave, prompt: "").count == 0)
    }

    @Test func aPipeIsNotInteractiveAndTheTestRunnerStdinMaybeNot() {
        // isInteractive() answers for the process's own terminal; here only that it does not crash.
        _ = Terminal.isInteractive()
    }
}
#endif

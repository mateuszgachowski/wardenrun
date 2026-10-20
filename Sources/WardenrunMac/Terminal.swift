#if canImport(Darwin)
import Darwin
import Foundation
import WardenrunCore

public enum TerminalError: Error, Equatable, Sendable {
    /// Not a terminal: a password is never read from a pipe or a file.
    case notInteractive
    case cancelled
    case endOfInput
    /// More than 1024 bytes. Longer input is refused, never cut.
    case tooLong
    case ioFailed
}

/// The hidden password prompt. The bytes go from the keyboard into a locked buffer one at a time;
/// no `String` and no growing array is involved, and the terminal settings are put back on every
/// way out.
public enum Terminal {
    static let maximumLength = 1024

    /// True when standard input and standard error are terminals (setup and `new` need one).
    public static func isInteractive() -> Bool {
        isatty(STDIN_FILENO) == 1 && isatty(STDERR_FILENO) == 1
    }

    /// Reads from the controlling terminal (`/dev/tty`), so that a pipe on standard input cannot
    /// stand in for the human.
    public static func readHidden(prompt: String) throws -> SecretBuffer {
        let descriptor = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC)
        guard descriptor >= 0 else { throw TerminalError.notInteractive }
        defer { close(descriptor) }
        return try readHidden(from: descriptor, to: descriptor, prompt: prompt)
    }

    /// The seam of the tests: any terminal descriptor pair. `onStagingBuffer` hands the working
    /// buffer to a test so that it can check it was wiped.
    static func readHidden(from input: Int32, to output: Int32, prompt: String,
                           onStagingBuffer: ((SecretBuffer) -> Void)? = nil) throws -> SecretBuffer {
        guard isatty(input) == 1 else { throw TerminalError.notInteractive }
        var original = termios()
        guard tcgetattr(input, &original) == 0 else { throw TerminalError.ioFailed }
        var raw = original
        // No echo, no line editing by the terminal driver, and no signals: Ctrl-C arrives as a
        // byte, so that this function (not a signal handler) puts the terminal back.
        raw.c_lflag &= ~tcflag_t(ECHO | ECHONL | ICANON | ISIG | IEXTEN)
        raw.c_cc.16 = 1   // VMIN
        raw.c_cc.17 = 0   // VTIME
        guard tcsetattr(input, TCSANOW, &raw) == 0 else { throw TerminalError.ioFailed }
        // Whatever was typed past the end of this read (the rest of an over-long password,
        // anything after Ctrl-C) is thrown away and cannot reach the shell afterwards. Not
        // TCSAFLUSH: that also waits for output to drain, which can block for good on a stopped
        // terminal.
        defer {
            var restore = original
            tcsetattr(input, TCSANOW, &restore)
            tcflush(input, TCIFLUSH)
        }

        let staging = SecretBuffer(count: maximumLength) { _ in }
        onStagingBuffer?(staging)
        defer { staging.wipe() }

        writeAll(output, prompt)
        defer { writeAll(output, "\n") }

        var length = 0
        var failure: TerminalError?
        read: while true {
            var byte: UInt8 = 0
            let count = Darwin.read(input, &byte, 1)
            if count < 0 {
                if errno == EINTR { continue }
                failure = errno == EIO ? .endOfInput : .ioFailed
                break
            }
            if count == 0 { failure = .endOfInput; break }
            switch byte {
            case 0x0A, 0x0D:
                break read
            case 0x03:
                failure = .cancelled
                break read
            case 0x04 where length == 0:
                failure = .endOfInput
                break read
            case 0x7F, 0x08:
                staging.withUnsafeMutableBytes { bytes in
                    // One character back: step over UTF-8 continuation bytes (10xxxxxx) too.
                    while length > 0 {
                        length -= 1
                        let wasContinuation = bytes[length] & 0xC0 == 0x80
                        bytes[length] = 0
                        if !wasContinuation { break }
                    }
                }
            case 0x1B:
                skipEscapeSequence(from: input)
            case 0x00..<0x20:
                continue read   // other control characters are not part of a password
            default:
                if length >= maximumLength {
                    failure = .tooLong
                    break read
                }
                staging.withUnsafeMutableBytes { $0[length] = byte }
                length += 1
            }
        }
        if let failure { throw failure }
        return staging.withUnsafeBytes { source in
            SecretBuffer(count: length) { destination in
                if let from = source.baseAddress, let to = destination.baseAddress, length > 0 { memcpy(to, from, length) }
            }
        }
    }

    /// After ESC: `[` or `O`, parameters, and one final byte. Arrow and function keys end up here.
    private static func skipEscapeSequence(from input: Int32) {
        var byte: UInt8 = 0
        guard Darwin.read(input, &byte, 1) == 1, byte == 0x5B || byte == 0x4F else { return }
        while Darwin.read(input, &byte, 1) == 1 {
            if byte >= 0x40 && byte <= 0x7E { return }
        }
    }

    private static func writeAll(_ descriptor: Int32, _ text: String) {
        let bytes = Array(text.utf8)
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
            if written < 0 && errno == EINTR { continue }
            if written <= 0 { return }
            offset += written
        }
    }
}
#endif

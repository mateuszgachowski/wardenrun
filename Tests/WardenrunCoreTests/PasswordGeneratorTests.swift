import Foundation
import Testing
@testable import WardenrunCore

/// Plays back a fixed list of bytes (cycling), and counts how many it handed out.
private final class ScriptedRandom: RandomSource, @unchecked Sendable {
    private let bytes: [UInt8]
    private let lock = NSLock()
    private var position = 0
    private(set) var handedOut = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    func fill(_ buffer: UnsafeMutableRawBufferPointer) throws {
        lock.lock(); defer { lock.unlock() }
        for index in 0..<buffer.count {
            buffer[index] = bytes[position % bytes.count]
            position += 1
        }
        handedOut += buffer.count
    }
}

private struct SystemRandom: RandomSource {
    func fill(_ buffer: UnsafeMutableRawBufferPointer) throws {
        var generator = SystemRandomNumberGenerator()
        for index in 0..<buffer.count { buffer[index] = UInt8.random(in: 0...255, using: &generator) }
    }
}

private struct FailingRandom: RandomSource {
    struct Broken: Error, Equatable {}
    var afterBytes = 0
    func fill(_ buffer: UnsafeMutableRawBufferPointer) throws {
        for index in 0..<min(afterBytes, buffer.count) { buffer[index] = 0x41 }
        throw Broken()
    }
}

private func text(_ buffer: SecretBuffer) -> String { buffer.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }

struct PasswordGeneratorTests {
    private let alnum = Set(PasswordGenerator.alnumAlphabet.utf8)
    private let full = Set(PasswordGenerator.fullAlphabet.utf8)

    @Test func theAlphabetsAreExactlyWhatTheDocsSay() {
        #expect(PasswordGenerator.alnumAlphabet == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        #expect(PasswordGenerator.alnumAlphabet.count == 62)
        #expect(PasswordGenerator.fullAlphabet.hasPrefix(PasswordGenerator.alnumAlphabet))
        #expect(Set(PasswordGenerator.fullAlphabet).count == PasswordGenerator.fullAlphabet.count, "no repeated character")
    }

    @Test func everyCharacterIsFromTheCharset() throws {
        for (charset, allowed) in [(PasswordCharset.alnum, alnum), (.full, full)] {
            var seen = Set<UInt8>()
            for _ in 0..<10_000 / 64 {
                let password = try PasswordGenerator.generate(length: 64, charset: charset, random: SystemRandom())
                password.withUnsafeBytes { for byte in $0 { seen.insert(byte) } }
            }
            #expect(seen.isSubset(of: allowed), "\(charset)")
            #expect(seen.count > allowed.count / 2, "\(charset) uses a good part of its alphabet")
        }
    }

    @Test func lengthIsExact16To128() throws {
        for length in [16, 17, 32, 100, 127, 128] {
            let password = try PasswordGenerator.generate(length: length, charset: .alnum, random: SystemRandom())
            #expect(password.count == length)
        }
        for bad in [-1, 0, 1, 15, 129, 1000] {
            #expect(throws: PasswordError.invalidLength) {
                _ = try PasswordGenerator.generate(length: bad, charset: .alnum, random: SystemRandom())
            }
        }
    }

    @Test func bytesAtOrAboveTheCutOffAreRejectedAndTheNextByteIsUsed() throws {
        // 62 characters: 248 = 4 * 62 is the cut-off. 255 and 248 are rejected, 0 and 1 are used.
        let random = ScriptedRandom([255, 248, 0, 1, 61, 62, 247])
        let password = try PasswordGenerator.draw(count: 5, alphabet: Array(PasswordGenerator.alnumAlphabet.utf8), random: random)
        let alphabet = Array(PasswordGenerator.alnumAlphabet)
        #expect(text(password) == String([alphabet[0], alphabet[1], alphabet[61], alphabet[0], alphabet[247 % 62]]))
    }

    @Test func rejectionSamplingHasNoModuloBiasExactly() throws {
        // One full turn of all 256 byte values gives each character exactly 256 / n times, rounded down.
        for (alphabet, expectedEach) in [(PasswordGenerator.alnumAlphabet, 4), (PasswordGenerator.fullAlphabet, 2)] {
            let letters = Array(alphabet.utf8)
            let accepted = letters.count * expectedEach
            let random = ScriptedRandom(Array(0...255))
            let password = try PasswordGenerator.draw(count: accepted, alphabet: letters, random: random)
            var counts: [UInt8: Int] = [:]
            password.withUnsafeBytes { for byte in $0 { counts[byte, default: 0] += 1 } }
            #expect(counts.count == letters.count)
            #expect(counts.values.allSatisfy { $0 == expectedEach }, "\(alphabet.count) characters: \(counts.values.sorted().first ?? 0)…\(counts.values.sorted().last ?? 0)")
        }
    }

    @Test func rejectionSamplingHasNoModuloBiasStatistically() throws {
        let letters = Array(PasswordGenerator.alnumAlphabet.utf8)
        let draws = 620_000
        let password = try PasswordGenerator.draw(count: draws, alphabet: letters, random: SystemRandom())
        var counts = [Int](repeating: 0, count: 256)
        password.withUnsafeBytes { for byte in $0 { counts[Int(byte)] += 1 } }
        let expected = Double(draws) / Double(letters.count)
        let chi = letters.reduce(0.0) { sum, letter in
            let difference = Double(counts[Int(letter)]) - expected
            return sum + difference * difference / expected
        }
        // 61 degrees of freedom; 0.001 tail is about 100. A modulo-biased generator scores far above 150 here.
        #expect(chi < 120, "chi-square \(chi)")
    }

    @Test func theFullCharsetHasNoQuoteBackslashBacktickDollarOrSpace() {
        for forbidden in ["\"", "'", "\\", "`", "$", " "] {
            #expect(!PasswordGenerator.fullAlphabet.contains(forbidden), "\(forbidden)")
        }
        #expect(PasswordGenerator.fullAlphabet.unicodeScalars.allSatisfy { $0.value > 0x20 && $0.value < 0x7F })
    }

    @Test func aFailingRandomSourceThrowsAndLeavesNothing() throws {
        #expect(throws: FailingRandom.Broken.self) {
            _ = try PasswordGenerator.generate(length: 32, charset: .alnum, random: FailingRandom())
        }
        #expect(throws: FailingRandom.Broken.self) {
            _ = try PasswordGenerator.generate(length: 32, charset: .alnum, random: FailingRandom(afterBytes: 10))
        }
    }

    @Test func eachPasswordDiffers() throws {
        var all = Set<String>()
        for _ in 0..<50 { all.insert(text(try PasswordGenerator.generate(length: 32, charset: .full, random: SystemRandom()))) }
        #expect(all.count == 50)
    }

    @Test func aSourceThatGivesOnlyRejectedBytesEndsInsteadOfSpinning() throws {
        #expect(throws: PasswordError.randomSourceExhausted) {
            _ = try PasswordGenerator.generate(length: 16, charset: .alnum, random: ScriptedRandom([255]))
        }
    }
}

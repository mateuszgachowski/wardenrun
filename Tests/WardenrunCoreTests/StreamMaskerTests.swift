import Foundation
import Testing
@testable import WardenrunCore

struct StreamMaskerTests {
    private func bytes(_ text: String) -> [UInt8] { Array(text.utf8) }
    private func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

    private func needle(_ value: String, as name: String = "x") -> Needle {
        Needle(bytes: bytes(value), replacement: bytes("[REDACTED:\(name)]"))
    }

    private func runChunked(_ input: [UInt8], needles: [Needle], sizes: [Int]) -> [UInt8] {
        let masker = StreamMasker(needles: needles)
        var out = [UInt8]()
        var index = 0
        var turn = 0
        while index < input.count {
            let size = max(1, sizes[turn % sizes.count])
            out += masker.feed(Array(input[index..<min(index + size, input.count)]))
            index += size
            turn += 1
        }
        out += masker.finish()
        return out
    }

    private func occurs(_ needle: [UInt8], in haystack: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        for start in 0...(haystack.count - needle.count) where haystack[start] == needle[0] {
            if Array(haystack[start..<(start + needle.count)]) == needle { return true }
        }
        return false
    }

    @Test func replacesAValue() {
        let out = StreamMasker.maskAll(bytes("a secret-value b"), needles: [needle("secret-value")])
        #expect(text(out) == "a [REDACTED:x] b")
    }

    @Test func everySplitPointGivesTheSameOutput() {
        let input = bytes("xx secret-value yy")
        let needles = [needle("secret-value")]
        for split in 0...input.count {
            let masker = StreamMasker(needles: needles)
            let out = masker.feed(Array(input[..<split])) + masker.feed(Array(input[split...])) + masker.finish()
            #expect(text(out) == "xx [REDACTED:x] yy", "split at \(split)")
        }
    }

    @Test func aSecretSplitBetweenTheLastChunkAndFinishIsStillCaught() {
        let masker = StreamMasker(needles: [needle("secret-value")])
        var out = masker.feed(bytes("tail secret-"))
        out += masker.feed(bytes("value"))
        out += masker.finish()
        #expect(text(out) == "tail [REDACTED:x]")
    }

    @Test func holdsBackExactlyTheLongestNeedleMinusOne() {
        let masker = StreamMasker(needles: [needle("0123456789ab")])   // 12 bytes
        #expect(masker.feed(bytes("zz")).isEmpty)
        let masker2 = StreamMasker(needles: [needle("0123456789ab")])
        let released = masker2.feed([UInt8](repeating: UInt8(ascii: "z"), count: 20))
        #expect(released.count == 20 - 11)
        #expect(masker2.finish().count == 11)
        #expect(text(masker.finish()) == "zz")
    }

    @Test func theLongerNeedleWinsWhenOneIsAPrefixOfTheOther() {
        let needles = [needle("abc123", as: "short"), needle("abc123def", as: "long")]
        #expect(text(StreamMasker.maskAll(bytes("abc123def"), needles: needles)) == "[REDACTED:long]")
        #expect(text(StreamMasker.maskAll(bytes("abc123xyz"), needles: needles)) == "[REDACTED:short]xyz")
    }

    @Test func adjacentSecretsAreBothReplaced() {
        let out = StreamMasker.maskAll(bytes("abc123abc123"), needles: [needle("abc123")])
        #expect(text(out) == "[REDACTED:x][REDACTED:x]")
    }

    @Test func overlappingNeedlesResolveLeftmostFirst() {
        let needles = [needle("abcdef", as: "one"), needle("defabc", as: "two")]
        let out = StreamMasker.maskAll(bytes("abcdefabcdef"), needles: needles)
        #expect(text(out) == "[REDACTED:one][REDACTED:one]")
        for n in needles { #expect(!occurs(n.bytes, in: out)) }
    }

    @Test func outputWithoutASecretIsUnchangedIncludingOddBytes() {
        let input: [UInt8] = [0x00, 0xFF, 0xFE, 0x41, 0x0A, 0x80, 0x7F]
        #expect(StreamMasker.maskAll(input, needles: [needle("secret-value")]) == input)
        #expect(runChunked(input, needles: [needle("secret-value")], sizes: [1]) == input)
    }

    @Test func anEmptyNeedleListPassesEverythingThrough() {
        let input = bytes("anything at all")
        let masker = StreamMasker(needles: [])
        #expect(masker.feed(input) == input)
        #expect(masker.finish().isEmpty)
    }

    @Test func randomChunkingNeverChangesTheOutputAndNeverLeaksAFullNeedle() {
        var random = SeededRandom(seed: 0xC0FFEE)
        let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,;!?@#$%^&*()+= ".utf8)
        for round in 0..<300 {
            let secrets = (0..<Int.random(in: 1...3, using: &random)).map { index in
                MaskSecret(name: "s\(index)", value: (0..<Int.random(in: 6...20, using: &random)).map { _ in
                    alphabet.randomElement(using: &random)!
                })
            }
            let plan = MaskNeedles.plan(for: secrets)
            var input = [UInt8]()
            for _ in 0..<Int.random(in: 0...6, using: &random) {
                input += (0..<Int.random(in: 0...40, using: &random)).map { _ in alphabet.randomElement(using: &random)! }
                let secret = secrets.randomElement(using: &random)!
                let variants = MaskNeedles.variants(of: secret.value)
                input += variants.randomElement(using: &random)!
            }
            let whole = StreamMasker.maskAll(input, needles: plan.needles)
            let sizes = (0..<8).map { _ in Int.random(in: 1...17, using: &random) }
            #expect(runChunked(input, needles: plan.needles, sizes: sizes) == whole, "round \(round)")
            #expect(runChunked(input, needles: plan.needles, sizes: [1]) == whole, "round \(round), byte by byte")
            for n in plan.needles { #expect(!occurs(n.bytes, in: whole), "round \(round) leaked \(text(n.bytes))") }
        }
    }
}

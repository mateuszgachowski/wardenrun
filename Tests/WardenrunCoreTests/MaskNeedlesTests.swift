import Foundation
import Testing
@testable import WardenrunCore

struct MaskNeedlesTests {
    private static let v = Array(#"Tr0ub4dor&3 x'"/\"#.utf8)

    private func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

    /// A literal backslash, and a JSON unicode escape built from it. Spelled out in pieces so that
    /// no tool or editor can quietly turn the written-out escape back into the character.
    private let bs = "\\"
    private func esc(_ hex: String) -> String { bs + "u" + hex }

    private func has(_ variants: [[UInt8]], _ expected: String, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(variants.contains(Array(expected.utf8)), "missing variant: \(expected)", sourceLocation: sourceLocation)
    }

    private func urlSafe(_ base64: String) -> String {
        base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
    }

    // MARK: encodings of a single-line value

    @Test func containsTheRawBytes() {
        has(MaskNeedles.variants(of: Self.v), #"Tr0ub4dor&3 x'"/\"#)
    }

    @Test func containsBase64InBothAlphabetsPaddedAndNot() {
        let variants = MaskNeedles.variants(of: Self.v)
        let std = Data(Self.v).base64EncodedString()
        let unpadded = std.replacingOccurrences(of: "=", with: "")
        has(variants, std)
        has(variants, unpadded)
        has(variants, urlSafe(std))
        has(variants, urlSafe(unpadded))
    }

    @Test func containsPercentEncodingInUppercaseLowercaseAndFormStyle() {
        let variants = MaskNeedles.variants(of: Self.v)
        has(variants, "Tr0ub4dor%263%20x%27%22%2F%5C")
        has(variants, "Tr0ub4dor%263%20x%27%22%2f%5c")
        has(variants, "Tr0ub4dor%263+x%27%22%2F%5C")
    }

    @Test func containsHexInBothCases() {
        let variants = MaskNeedles.variants(of: Self.v)
        has(variants, Hex.encode(Self.v))
        has(variants, Hex.encode(Self.v, uppercase: true))
    }

    @Test func containsJSONStringBodies() {
        let variants = MaskNeedles.variants(of: Self.v)
        has(variants, #"Tr0ub4dor&3 x'\"/\\"#)            // minimal escaping
        has(variants, #"Tr0ub4dor&3 x'\"\/\\"#)           // slash escaped
        has(variants, "Tr0ub4dor" + esc("0026") + "3 x'" + bs + "\"/" + bs + bs)   // HTML-safe encoders escape &, <, >
    }

    @Test func containsHTMLSafeJSONForAngleBrackets() {
        let variants = MaskNeedles.variants(of: Array("a<b>&cd".utf8))
        has(variants, "a" + esc("003c") + "b" + esc("003e") + esc("0026") + "cd")
    }

    @Test func containsASCIIOnlyJSONForNonASCIIValues() {
        let variants = MaskNeedles.variants(of: Array("zażółć-gęślą".utf8))
        has(variants, "zażółć-gęślą")
        has(variants, "za" + esc("017c") + esc("00f3") + esc("0142") + esc("0107") + "-g" + esc("0119") + esc("015b") + "l" + esc("0105"))
    }

    @Test func containsSingleQuoteShellBody() {
        has(MaskNeedles.variants(of: Self.v), #"Tr0ub4dor&3 x'\''"/\"#)
    }

    // MARK: base64 inside a bigger stream

    @Test(arguments: Array(0...8), [0, 5])
    func base64OfTheValueInsideAStreamIsDetectedAtEveryAlignment(offset: Int, trailing: Int) {
        for value in [Self.v, Array("abcdef".utf8)] {
            let variants = MaskNeedles.variants(of: value).map(text)
            let before: [UInt8] = (0..<offset).map { UInt8(0xA0 + $0) }
            let after: [UInt8] = (0..<trailing).map { UInt8(0x90 + $0) }
            let stream: [UInt8] = before + value + after
            let std = Data(stream).base64EncodedString()
            let unpadded = std.replacingOccurrences(of: "=", with: "")
            for encoded in [std, unpadded, urlSafe(std), urlSafe(unpadded)] {
                #expect(variants.contains { encoded.contains($0) },
                        "offset \(offset), trailing \(trailing), value \(value.count) bytes: \(encoded)")
            }
        }
    }

    // MARK: multi-line, odd bytes, size limits

    @Test func multiLineValuesAreAlsoMatchedPerLine() {
        let value = Array("line one secret\nline two secret\r\n".utf8)
        let variants = MaskNeedles.variants(of: value)
        has(variants, "line one secret")
        has(variants, "line two secret")
        has(variants, Data(Array("line one secret".utf8)).base64EncodedString())
        #expect(!variants.contains([]))
        #expect(variants.contains(value))
    }

    @Test func aSingleLineValueWithATrailingNewlineIsAlsoMatchedWithoutIt() {
        has(MaskNeedles.variants(of: Array("sixsix\n".utf8)), "sixsix")
    }

    @Test func bytesThatAreNotUTF8DoNotCrashAndStillGetRawHexAndBase64() {
        let value: [UInt8] = [0x00, 0xFF, 0xFE, 0x41, 0x42, 0x43, 0x44]
        let variants = MaskNeedles.variants(of: value)
        #expect(variants.contains(value))
        has(variants, Hex.encode(value))
        has(variants, Data(value).base64EncodedString())
    }

    @Test func aNulInsideAValueIsEscapedInTheJSONForm() {
        let variants = MaskNeedles.variants(of: Array("abc\u{0}def".utf8))
        has(variants, #"abc\u0000def"#)
    }

    @Test func valuesShorterThanTheMinimumHaveNoVariants() {
        #expect(MaskNeedles.minimumLength == 6)
        #expect(MaskNeedles.variants(of: [1, 2, 3]).isEmpty)
        #expect(MaskNeedles.variants(of: Array("12345".utf8)).isEmpty)
        #expect(!MaskNeedles.variants(of: Array("123456".utf8)).isEmpty)
    }

    @Test func noVariantIsShorterThanTheMinimumAndTheListHasNoDuplicates() {
        let variants = MaskNeedles.variants(of: Array("abcdef".utf8))
        #expect(variants.allSatisfy { $0.count >= MaskNeedles.minimumLength })
        #expect(Set(variants).count == variants.count)
    }

    @Test func variantsAreOrderedLongestFirstThenLexicographically() {
        let variants = MaskNeedles.variants(of: Self.v)
        for (a, b) in zip(variants, variants.dropFirst()) {
            #expect(a.count > b.count || (a.count == b.count && a.lexicographicallyPrecedes(b)))
        }
    }

    // MARK: plan

    @Test func planAttachesTheReplacementAndReportsShortValues() {
        let plan = MaskNeedles.plan(for: [
            MaskSecret(name: "token", value: Array("abcdef".utf8)),
            MaskSecret(name: "short", value: [1, 2, 3]),
            MaskSecret(name: "empty", value: []),
        ])
        #expect(plan.tooShort == ["short", "empty"])
        #expect(!plan.needles.isEmpty)
        #expect(plan.needles.allSatisfy { $0.replacement == Array("[REDACTED:token]".utf8) })
        #expect(plan.needles.contains { $0.bytes == Array("abcdef".utf8) })
    }

    @Test func planUsesACustomReplacement() {
        let plan = MaskNeedles.plan(for: [MaskSecret(name: "k", value: Array("abcdef".utf8))],
                                    replacement: { "<<\($0)>>" })
        #expect(plan.needles.allSatisfy { $0.replacement == Array("<<k>>".utf8) })
    }

    @Test func planKeepsTheOrderOfTheSecrets() {
        let plan = MaskNeedles.plan(for: [
            MaskSecret(name: "a", value: Array("aaaaaa".utf8)),
            MaskSecret(name: "b", value: Array("bbbbbb".utf8)),
        ])
        let names = plan.needles.map { String(decoding: $0.replacement, as: UTF8.self) }
        let firstB = names.firstIndex(of: "[REDACTED:b]")!
        #expect(names[..<firstB].allSatisfy { $0 == "[REDACTED:a]" })
    }
}

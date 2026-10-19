import Testing
@testable import WardenrunCore

struct HexTests {
    @Test func encodesLowercaseByDefault() {
        #expect(Hex.encode([0x00, 0xff, 0x1a]) == "00ff1a")
    }

    @Test func encodesUppercaseOnRequest() {
        #expect(Hex.encode([0x00, 0xff, 0x1a], uppercase: true) == "00FF1A")
    }

    @Test func decodesMixedCase() {
        #expect(Hex.decode("00FF1a") == [0, 255, 26])
    }

    @Test func decodesEmptyToEmpty() {
        #expect(Hex.decode("") == [])
    }

    @Test func rejectsOddLength() {
        #expect(Hex.decode("abc") == nil)
    }

    @Test func rejectsNonHexCharacters() {
        #expect(Hex.decode("zz") == nil)
    }
}

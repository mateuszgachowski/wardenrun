#if canImport(CryptoKit)
import CryptoKit
import Foundation
import Testing
import WardenrunCore

/// Cross-check against the platform implementation. Names are qualified because
/// CryptoKit has its own `SHA256`.
struct SHA256CryptoKitTests {
    @Test func matchesCryptoKitOnPseudoRandomInputs() {
        var state: UInt64 = 0x9E37_79B9_7F4A_7C15
        func next() -> UInt64 {
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            return state
        }
        for _ in 0..<200 {
            let length = Int(next() % 301)
            let message = (0..<length).map { _ in UInt8(truncatingIfNeeded: next()) }
            let expected = Array(CryptoKit.SHA256.hash(data: Data(message)))
            #expect(WardenrunCore.SHA256.hash(message) == expected)
        }
    }
}
#endif

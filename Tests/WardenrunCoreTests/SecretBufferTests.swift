import Foundation
import Testing
@testable import WardenrunCore

struct SecretBufferTests {
    private let secret = Array("hunter2-hunter2".utf8)

    @Test func contentsAreReadableUntilWiped() {
        let buffer = SecretBuffer(copying: secret)
        #expect(buffer.count == 15)
        #expect(buffer.isWiped == false)
        let copy = buffer.withUnsafeBytes { Array($0) }
        #expect(copy == secret)
    }

    @Test func wipeZeroesTheStorageInPlace() {
        let buffer = SecretBuffer(copying: secret)
        buffer.wipe()
        #expect(buffer.isWiped)
        #expect(buffer.count == 0)
        #expect(buffer.withUnsafeBytes { $0.count } == 0)
        // The allocation outlives wipe() until deinit, so the zeroing can be observed.
        let raw = buffer.storageForTesting
        #expect(raw.count >= secret.count)
        #expect(raw.allSatisfy { $0 == 0 })
    }

    @Test func wipingTwiceIsHarmless() {
        let buffer = SecretBuffer(copying: secret)
        buffer.wipe()
        buffer.wipe()
        #expect(buffer.isWiped)
    }

    @Test func anEmptyBufferWorks() {
        let buffer = SecretBuffer(copying: [])
        #expect(buffer.count == 0)
        #expect(buffer.withUnsafeBytes { $0.count } == 0)
    }

    @Test func lockedStateIsReportedWithoutFailingWhenMlockIsRefused() {
        // mlock can fail under a small RLIMIT_MEMLOCK; the buffer must work either way.
        let buffer = SecretBuffer(copying: secret)
        _ = buffer.isLocked
        #expect(buffer.withUnsafeBytes { Array($0) } == secret)
    }

    @Test func printingNeverShowsTheContent() {
        let buffer = SecretBuffer(copying: secret)
        let hex = Hex.encode(secret)
        var dumped = ""
        dump(buffer, to: &dumped)
        for text in ["\(buffer)", String(reflecting: buffer), dumped] {
            #expect(!text.contains("hunter2"))
            #expect(!text.contains(hex))
        }
        #expect("\(buffer)" == "SecretBuffer(15 bytes)")
        buffer.wipe()
        #expect("\(buffer)" == "SecretBuffer(wiped)")
    }
    @Test func initWithFillProducesABufferOfTheExactSize() {
        let buffer = SecretBuffer(count: 5) { raw in
            #expect(raw.count == 5)
            for index in 0..<5 { raw[index] = UInt8(65 + index) }
        }
        #expect(buffer.count == 5)
        #expect(buffer.withUnsafeBytes { Array($0) } == Array("ABCDE".utf8))
        buffer.wipe()
        #expect(buffer.storageForTesting.allSatisfy { $0 == 0 })
    }

    @Test func initWithFillAndZeroCountGivesAnEmptyBuffer() {
        let buffer = SecretBuffer(count: 0) { raw in #expect(raw.count == 0) }
        #expect(buffer.count == 0)
    }

    private struct FillFailed: Error {}

    @Test func aThrowingFillPropagatesItsError() {
        #expect(throws: FillFailed.self) {
            _ = try SecretBuffer(count: 8) { _ in throw FillFailed() }
        }
    }

    @Test func mutableAccessWritesInPlaceAndWipeStillZeroesIt() {
        let buffer = SecretBuffer(count: 4) { _ in }
        buffer.withUnsafeMutableBytes { bytes in
            bytes[0] = 7
            bytes[3] = 9
        }
        #expect(buffer.withUnsafeBytes { Array($0) } == [7, 0, 0, 9])
        buffer.wipe()
        #expect(buffer.storageForTesting.allSatisfy { $0 == 0 })
    }
}

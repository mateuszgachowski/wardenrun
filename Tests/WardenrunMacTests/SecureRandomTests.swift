#if canImport(Darwin)
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

struct SecureRandomTests {
    private func bytes(_ count: Int) throws -> [UInt8] {
        var result = [UInt8](repeating: 0, count: count)
        try result.withUnsafeMutableBytes { try SecureRandom().fill($0) }
        return result
    }

    @Test func fillsTheWholeBufferWithBytesThatDiffer() throws {
        let first = try bytes(64), second = try bytes(64)
        #expect(first != second)
        #expect(first.contains { $0 != 0 })
        #expect(Set(first).count > 20, "64 random bytes are not 20 or fewer distinct values")
    }

    @Test func anEmptyBufferIsFine() throws {
        #expect(try bytes(0).isEmpty)
    }

    @Test func itDrivesThePasswordGenerator() throws {
        let password = try PasswordGenerator.generate(length: 40, charset: .full, random: SecureRandom())
        #expect(password.count == 40)
        let printable = password.withUnsafeBytes { Array($0).allSatisfy { $0 > 0x20 && $0 < 0x7F } }
        #expect(printable)
    }
}
#endif

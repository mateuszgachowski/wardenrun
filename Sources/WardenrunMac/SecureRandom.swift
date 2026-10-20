#if canImport(Darwin)
import Foundation
import Security
import WardenrunCore

/// The system's cryptographic random source (`SecRandomCopyBytes`), for `wardenrun new`.
public struct SecureRandom: RandomSource {
    public struct Failure: Error, Equatable, Sendable {
        public let status: Int32
    }

    public init() {}

    public func fill(_ buffer: UnsafeMutableRawBufferPointer) throws {
        guard buffer.count > 0, let base = buffer.baseAddress else { return }
        let status = SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        guard status == errSecSuccess else { throw Failure(status: status) }
    }
}
#endif

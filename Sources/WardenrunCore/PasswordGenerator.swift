import Foundation

/// Where random bytes come from. macOS uses `SecRandomCopyBytes`; tests use scripted bytes.
public protocol RandomSource: Sendable {
    func fill(_ buffer: UnsafeMutableRawBufferPointer) throws
}

public enum PasswordError: Error, Equatable, Sendable {
    case invalidLength
    /// The source kept giving bytes that are all rejected; it is broken, so the generator gives up.
    case randomSourceExhausted

    public var message: String {
        switch self {
        case .invalidLength: return "the password length must be between 16 and 128"
        case .randomSourceExhausted: return "the random source did not deliver usable bytes"
        }
    }
}

/// Makes the password `wardenrun new` stores (DESIGN 5.6). The password is written straight into a
/// `SecretBuffer`; the random bytes pass through a second one that is wiped. Characters are chosen
/// by rejection sampling: a byte at or above the largest multiple of the alphabet size that fits
/// in 256 is thrown away, so every character is equally likely.
public enum PasswordGenerator {
    static let alnumAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    /// Letters, digits and symbols that need no quoting in a URL-free, shell-free context: no
    /// quote of either kind, backslash, backtick, dollar sign or space.
    static let fullAlphabet = alnumAlphabet + "!#%&()*+,-./:;<=>?@[]^_{|}~"

    public static func generate(length: Int, charset: PasswordCharset, random: RandomSource) throws -> SecretBuffer {
        guard (16...128).contains(length) else { throw PasswordError.invalidLength }
        let alphabet = charset == .alnum ? alnumAlphabet : fullAlphabet
        return try draw(count: length, alphabet: Array(alphabet.utf8), random: random)
    }

    static func draw(count: Int, alphabet: [UInt8], random: RandomSource) throws -> SecretBuffer {
        precondition(!alphabet.isEmpty && alphabet.count <= 256)
        let cutoff = 256 - (256 % alphabet.count)
        let pool = SecretBuffer(count: 256) { _ in }
        defer { pool.wipe() }
        var rounds = 0
        let maximumRounds = count + 64
        return try SecretBuffer(count: count) { destination in
            var written = 0
            while written < count {
                rounds += 1
                guard rounds <= maximumRounds else { throw PasswordError.randomSourceExhausted }
                try pool.withUnsafeMutableBytes { try random.fill($0) }
                pool.withUnsafeBytes { bytes in
                    for byte in bytes where Int(byte) < cutoff {
                        destination[written] = alphabet[Int(byte) % alphabet.count]
                        written += 1
                        if written == count { break }
                    }
                }
            }
        }
    }
}

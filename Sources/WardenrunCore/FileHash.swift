import Foundation

public enum FileHashError: Error, Equatable {
    case unreadable(String)
}

public enum FileHash {
    /// SHA-256 of the file's contents as lowercase hex, read in blocks.
    public static func sha256(ofFileAt path: String) throws -> String {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC)
        guard descriptor >= 0 else { throw FileHashError.unreadable(path) }
        defer { close(descriptor) }
        var hasher = SHA256()
        var block = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = read(descriptor, &block, block.count)
            if count < 0 { throw FileHashError.unreadable(path) }
            if count == 0 { break }
            block.withUnsafeBytes { hasher.update(UnsafeRawBufferPointer(rebasing: $0[0..<count])) }
        }
        return Hex.encode(hasher.finalize())
    }
}

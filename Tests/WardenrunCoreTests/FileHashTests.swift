import Foundation
import Testing
@testable import WardenrunCore

struct FileHashTests {
    @Test func knownVectorForABC() throws {
        let hash = try withTempDirectory { dir in
            try FileHash.sha256(ofFileAt: writeFile(dir + "/f", "abc", mode: 0o644))
        }
        #expect(hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func anEmptyFile() throws {
        let hash = try withTempDirectory { dir in
            try FileHash.sha256(ofFileAt: writeFile(dir + "/f", "", mode: 0o644))
        }
        #expect(hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test func aFileLargerThanOneReadBlockMatchesTheInMemoryHash() throws {
        let bytes = (0..<200_000).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }
        let hash = try withTempDirectory { dir in
            let path = dir + "/big"
            FileManager.default.createFile(atPath: path, contents: Data(bytes))
            return try FileHash.sha256(ofFileAt: path)
        }
        #expect(hash == SHA256.hexHash(bytes))
    }

    @Test func aMissingFileThrows() {
        #expect(throws: FileHashError.unreadable("/nonexistent/wardenrun/file")) {
            _ = try FileHash.sha256(ofFileAt: "/nonexistent/wardenrun/file")
        }
    }

    @Test func aDirectoryThrows() {
        withTempDirectory { dir in
            #expect(throws: FileHashError.unreadable(dir)) { _ = try FileHash.sha256(ofFileAt: dir) }
        }
    }
}

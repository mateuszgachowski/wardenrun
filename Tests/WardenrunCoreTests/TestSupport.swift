/// Deterministic generator so the randomized tests are reproducible.
struct SeededRandom: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

import Foundation

/// Runs `body` with a fresh empty directory that is removed afterwards.
func withTempDirectory<T>(_ body: (String) throws -> T) rethrows -> T {
    let path = (NSTemporaryDirectory() as NSString).appendingPathComponent("wardenrun-test-" + UUID().uuidString)
    try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: path) }
    return try body(path)
}

/// Permission bits (`0o600` style) of a path, or nil when it does not exist.
func permissionBits(of path: String) -> Int? {
    var info = stat()
    guard stat(path, &info) == 0 else { return nil }
    return Int(info.st_mode & 0o777)
}

/// `realpath(3)` as a String; the temp directory on macOS sits behind the /var -> /private/var link.
func realPath(_ path: String) -> String {
    guard let resolved = realpath(path, nil) else { return path }
    defer { free(resolved) }
    return String(cString: resolved)
}

/// Writes a small file with the given permission bits and returns its path.
@discardableResult
func writeFile(_ path: String, _ contents: String = "#!/bin/sh\necho hi\n", mode: Int = 0o755) -> String {
    try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                             withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: path, contents: Data(contents.utf8))
    chmod(path, mode_t(mode))
    return path
}

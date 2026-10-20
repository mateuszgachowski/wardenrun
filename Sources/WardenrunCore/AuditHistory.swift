import Foundation

extension AuditLog {
    /// How much of the end of the log `lastApprovedHash` reads.
    static let historyWindow = 8 * 1024 * 1024

    /// The program hash recorded by the newest `approved` line for this item and executable path,
    /// or nil: no such line in the last `historyWindow` bytes, no log, an unreadable one. The
    /// approval text uses it to say `[executable changed]`; a nil only means "nothing to compare
    /// with", never an error, and a damaged line is skipped (the log is not a trust anchor,
    /// threat model row 11).
    public static func lastApprovedHash(path: String, item: String, executable: String) -> String? {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0 else { return nil }

        let size = Int(info.st_size)
        let length = min(size, historyWindow)
        var buffer = [UInt8](repeating: 0, count: length)
        var filled = 0
        while filled < length {
            let count = buffer[filled...].withUnsafeMutableBytes { pread(descriptor, $0.baseAddress, $0.count, off_t(size - length + filled)) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return nil }
            filled += count
        }

        var lines = buffer.split(separator: 0x0A, omittingEmptySubsequences: true).map { Array($0) }
        // The first line of a tail that starts inside the file is usually cut in the middle.
        if size > length, !lines.isEmpty { lines.removeFirst() }
        for line in lines.reversed() {
            guard let object = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
                  object["event"] as? String == AuditEventKind.approved.rawValue,
                  object["item"] as? String == item,
                  object["executable"] as? String == executable,
                  let hash = object["executable_sha256"] as? String, hash.count == 64,
                  hash.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { continue }
            return hash
        }
        return nil
    }
}

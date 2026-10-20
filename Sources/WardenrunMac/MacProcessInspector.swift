#if canImport(Darwin)
import Darwin
import Foundation
import WardenrunCore

/// Who started wardenrun, for the approval text and the audit log: the executable of the parent
/// and of each ancestor, from the process table of the kernel (`libproc`). The names are shown to
/// the human as information; nothing is decided from them, because a parent can be anything the
/// agent chooses to start wardenrun from.
public struct MacProcessInspector: ProcessInspector {
    public init() {}

    /// A longer chain is cut here. Real chains are a handful long; the bound also ends a cycle.
    static let maximumDepth = 20

    public func parentChain(of pid: Int32) -> [ProcessRecord] {
        var chain: [ProcessRecord] = []
        var seen: Set<Int32> = [pid]
        var current = pid
        while chain.count < Self.maximumDepth {
            guard let parent = Self.parentPID(of: current), parent > 1, seen.insert(parent).inserted,
                  let path = Self.executablePath(of: parent) else { break }
            chain.append(ProcessRecord(pid: parent, path: path))
            current = parent
        }
        return chain
    }

    private static func parentPID(of pid: Int32) -> Int32? {
        guard pid > 0 else { return nil }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return Int32(bitPattern: info.pbi_ppid)
    }

    private static func executablePath(of pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }
}
#endif

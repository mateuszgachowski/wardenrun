/// Replaces secret values in a byte stream that arrives in arbitrary chunks.
///
/// Matching is leftmost first; among needles that start at the same byte the longest wins.
/// `feed` keeps back the last `longest needle - 1` bytes, so a value split across two chunks
/// is still found. Use one masker per stream (stdout and stderr are separate streams).
///
/// Known limit: when two different secrets overlap partially, the later one is consumed up
/// to the end of the earlier one and its remaining tail is not masked. Masking is an
/// accident guard, not an exfiltration barrier.
public final class StreamMasker {
    private let needles: [Needle]
    private let candidatesByFirstByte: [[Int]]
    private let holdBack: Int
    private var held = [UInt8]()

    public init(needles: [Needle]) {
        let usable = needles.filter { !$0.bytes.isEmpty }
        self.needles = usable
        var table = [[Int]](repeating: [], count: 256)
        for (index, needle) in usable.enumerated() { table[Int(needle.bytes[0])].append(index) }
        candidatesByFirstByte = table.map { indexes in
            indexes.sorted { a, b in
                usable[a].bytes.count != usable[b].bytes.count ? usable[a].bytes.count > usable[b].bytes.count : a < b
            }
        }
        holdBack = max((usable.map { $0.bytes.count }.max() ?? 1) - 1, 0)
    }

    /// Returns the bytes that are safe to release; the rest stays inside until more arrives.
    public func feed(_ chunk: [UInt8]) -> [UInt8] {
        held += chunk
        let limit = held.count - holdBack
        return process(upTo: max(limit, 0))
    }

    /// Releases everything that is left. The masker is empty afterwards.
    public func finish() -> [UInt8] {
        process(upTo: held.count)
    }

    public static func maskAll(_ input: [UInt8], needles: [Needle]) -> [UInt8] {
        let masker = StreamMasker(needles: needles)
        return masker.feed(input) + masker.finish()
    }

    /// Scans start positions below `limit`; a match needs all its bytes inside `held`.
    private func process(upTo limit: Int) -> [UInt8] {
        var out = [UInt8]()
        var index = 0
        while index < limit {
            if let match = longestMatch(at: index) {
                out += needles[match].replacement
                index += needles[match].bytes.count
            } else {
                out.append(held[index])
                index += 1
            }
        }
        held.removeFirst(index)
        return out
    }

    private func longestMatch(at start: Int) -> Int? {
        for candidate in candidatesByFirstByte[Int(held[start])] {
            let bytes = needles[candidate].bytes
            guard start + bytes.count <= held.count else { continue }
            var matches = true
            for offset in 1..<bytes.count where held[start + offset] != bytes[offset] {
                matches = false
                break
            }
            if matches { return candidate }
        }
        return nil
    }
}

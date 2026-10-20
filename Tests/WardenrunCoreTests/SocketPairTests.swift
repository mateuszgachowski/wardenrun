import Foundation
import Testing
@testable import WardenrunCore

struct SocketPairTests {
    @Test func bytesFlowBothWays() throws {
        let (a, b) = try SocketPair.make()
        defer { close(a); close(b) }
        #expect(write(a, "ab", 2) == 2)
        var buffer = [UInt8](repeating: 0, count: 4)
        #expect(read(b, &buffer, 4) == 2)
        #expect(write(b, "c", 1) == 1)
        #expect(read(a, &buffer, 4) == 1)
        #expect(buffer[0] == UInt8(ascii: "c"))
    }

    @Test func bothEndsAreCloseOnExec() throws {
        let (a, b) = try SocketPair.make()
        defer { close(a); close(b) }
        for descriptor in [a, b] {
            let flags = fcntl(descriptor, F_GETFD)
            #expect(flags >= 0 && flags & FD_CLOEXEC != 0)
        }
    }

    @Test func writingToAClosedPeerFailsInsteadOfRaisingSIGPIPE() throws {
        let (a, b) = try SocketPair.make()
        close(b)
        defer { close(a) }
        var result = 0
        for _ in 0..<3 { result = SocketPair.send(a, [1, 2, 3]) }
        #expect(result < 0)
        #expect(errno == EPIPE)
    }
}

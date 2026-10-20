#if canImport(Darwin)
import Darwin
import Foundation
import Testing
import WardenrunCore
@testable import WardenrunMac

struct ProcessInspectorTests {
    private let inspector = MacProcessInspector()

    @Test func chainOfTheTestProcessStartsWithItsParentAndEndsBeforeLaunchd() throws {
        let chain = inspector.parentChain(of: getpid())
        let parent = try #require(chain.first)
        #expect(parent.pid == getppid())
        #expect(!parent.path.isEmpty && parent.path.hasPrefix("/"))
        #expect(chain.allSatisfy { $0.pid > 1 }, "launchd must not be part of the chain")
        #expect(Set(chain.map(\.pid)).count == chain.count, "a process appears once")
    }

    @Test func aDeadPidGivesAnEmptyChain() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run()
        child.waitUntilExit()
        #expect(inspector.parentChain(of: child.processIdentifier).isEmpty)
        #expect(inspector.parentChain(of: 0).isEmpty)
        #expect(inspector.parentChain(of: -5).isEmpty)
    }

    @Test func chainIsBoundedAtTwentyEntries() {
        #expect(inspector.parentChain(of: getpid()).count <= MacProcessInspector.maximumDepth)
        #expect(MacProcessInspector.maximumDepth == 20)
    }

    @Test func aChainFollowsRealParentsOfAShell() throws {
        // sh -> sh: the inner shell's chain starts with the outer one.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "/bin/sleep 5 & echo $!; wait"]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        defer { process.terminate() }
        let line = String(decoding: pipe.fileHandleForReading.availableData, as: UTF8.self)
        let sleeper = try #require(Int32(line.trimmingCharacters(in: .whitespacesAndNewlines)))
        defer { kill(sleeper, SIGKILL) }
        let chain = inspector.parentChain(of: sleeper)
        #expect(chain.first?.pid == process.processIdentifier)
        #expect(["/bin/sh", "/bin/bash"].contains(chain.first?.path ?? ""))   // sh is bash on macOS
        #expect(chain.dropFirst().first?.pid == getpid())
    }
}
#endif

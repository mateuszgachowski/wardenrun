#if canImport(Darwin)
import Darwin
import Foundation
import Testing
@testable import WardenrunMac

@Suite(.serialized)
struct ProcessStartTests {
    @Test func closedStandardDescriptorsAreReplacedByDevNull() {
        let numbers: [Int32] = [210, 211, 212]
        // 211 stays open as a pipe; the other two are closed.
        var fds: [Int32] = [-1, -1]
        #expect(pipe(&fds) == 0)
        #expect(dup2(fds[0], 211) == 211)
        close(fds[0])
        defer { for number in numbers { close(number) }; close(fds[1]) }
        for number in [210, 212] as [Int32] { close(number) }

        ProcessStart.ensureOpen(numbers)

        for number in numbers { #expect(fcntl(number, F_GETFD) >= 0, "\(number)") }
        var info = stat()
        #expect(fstat(210, &info) == 0 && info.st_mode & S_IFMT == S_IFCHR, "210 is /dev/null")
        #expect(fstat(212, &info) == 0 && info.st_mode & S_IFMT == S_IFCHR, "212 is /dev/null")
        #expect(fstat(211, &info) == 0 && info.st_mode & S_IFMT == S_IFIFO, "211 was open and is left alone")
    }

    @Test func prepareIgnoresSIGPIPEAndRestoresTheDefaultForSIGCHLD() {
        var ignoreChild = sigaction(), oldChild = sigaction(), oldPipe = sigaction()
        ignoreChild.__sigaction_u.__sa_handler = SIG_IGN
        sigemptyset(&ignoreChild.sa_mask)
        sigaction(SIGCHLD, &ignoreChild, &oldChild)
        sigaction(SIGPIPE, nil, &oldPipe)
        defer { sigaction(SIGCHLD, &oldChild, nil); sigaction(SIGPIPE, &oldPipe, nil) }

        ProcessStart.prepare()

        var child = sigaction(), pipeAction = sigaction()
        sigaction(SIGCHLD, nil, &child)
        sigaction(SIGPIPE, nil, &pipeAction)
        #expect(unsafeBitCast(child.__sigaction_u.__sa_handler, to: Int.self) == 0, "SIG_DFL")
        #expect(unsafeBitCast(pipeAction.__sigaction_u.__sa_handler, to: Int.self) == 1, "SIG_IGN")
    }

    @Test func prepareOpensWhatIsClosedOfTheStandardDescriptors() {
        let numbers: [Int32] = [215, 216]
        defer { for number in numbers { close(number) } }
        for number in numbers { close(number) }
        ProcessStart.prepare(standardDescriptors: numbers)
        for number in numbers { #expect(fcntl(number, F_GETFD) >= 0, "\(number)") }
    }

    @Test func writingToAPipeNobodyReadsDoesNotKillTheProcess() {
        ProcessStart.prepare()
        var fds: [Int32] = [-1, -1]
        #expect(pipe(&fds) == 0)
        close(fds[0])
        defer { close(fds[1]) }
        ProcessStart.write(fds[1], "wardenrun: a message nobody will read\n")
        #expect(Bool(true), "still alive")
    }
}
#endif

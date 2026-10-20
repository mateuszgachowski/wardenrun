import Foundation
import WardenrunCore

#if canImport(Darwin)
import WardenrunMac

// Exit codes: 0 done, 1 doctor found a failure or setup/run/new failed, 64 bad command line or no
// terminal, 77 not approved (run/new), 78 refused to start in an unsafe state, 126 and 127 the
// command could not be run / was not found; `run` otherwise returns the command's own status
// (128 plus the signal number when it was killed).

func say(_ text: String) { FileHandle.standardOutput.write(Data((text + "\n").utf8)) }
func complain(_ text: String) { FileHandle.standardError.write(Data(("wardenrun: " + text + "\n").utf8)) }

/// The home directory from the user database, not from `$HOME`: the caller controls the
/// environment, and `$HOME` decides where wardenrun's `bw` profile and state live.
func homeDirectory() -> String {
    var entry = passwd()
    var result: UnsafeMutablePointer<passwd>?
    var buffer = [CChar](repeating: 0, count: 4096)
    if getpwuid_r(getuid(), &entry, &buffer, buffer.count, &result) == 0, result != nil, let directory = entry.pw_dir {
        return String(cString: directory)
    }
    return NSHomeDirectory()
}

// Hardening comes first, before anything that could hold a secret.
let hardening = Hardening.apply()
let environment = ProcessInfo.processInfo.environment

let command: Command
do {
    command = try CommandParser.parse(Array(CommandLine.arguments.dropFirst()))
} catch let error as UsageError {
    complain(error.message)
    complain("try `wardenrun help`")
    exit(64)
} catch {
    complain("the command line could not be read")
    exit(64)
}

/// `setup`, `run` and `new` start only in a state where the checks pass. A build from source
/// (no hardened runtime) may run only if it is a debug build: a switch anybody could set from the
/// environment would not be a protection.
func refuseUnlessSafe() {
    #if DEBUG
    let allowUnhardened = true
    #else
    let allowUnhardened = false
    #endif
    let checks = hardening + Hardening.selfCheck(environment: environment)
    if let reason = StartupPolicy.refusal(checks: checks, allowUnhardened: allowUnhardened) {
        complain(reason)
        exit(78)
    }
}

switch command {
case .help:
    say(Usage.text)
case .version:
    say("wardenrun \(WardenrunVersion.current)")
case .doctor:
    // The start-up results (debugger attach denied, core dumps off) are part of the report.
    let report = DoctorRunner.run(environment: environment, store: KeychainAclStore(),
                                  paths: WardenrunPaths(home: homeDirectory()),
                                  hardening: { hardening + Hardening.selfCheck(environment: $0) })
    FileHandle.standardOutput.write(Data(report.render().utf8))
    exit(report.exitCode)
case .setup(let options):
    refuseUnlessSafe()
    exit(SetupCommand.run(options: options, environment: environment, paths: WardenrunPaths(home: homeDirectory()),
                          store: KeychainAclStore(), output: say,
                          errorOutput: { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }))
case .run(let options):
    refuseUnlessSafe()
    exit(RunCommand.run(options: options, environment: environment, paths: WardenrunPaths(home: homeDirectory()),
                        store: KeychainAclStore(),
                        errorOutput: { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }))
case .new(let options):
    refuseUnlessSafe()
    exit(NewCommand.run(options: options, environment: environment, paths: WardenrunPaths(home: homeDirectory()),
                        store: KeychainAclStore(), output: say,
                        errorOutput: { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }))
}
#else
FileHandle.standardError.write(Data("wardenrun runs on macOS only\n".utf8))
exit(70)
#endif

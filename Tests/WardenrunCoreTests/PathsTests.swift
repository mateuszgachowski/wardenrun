import Testing
@testable import WardenrunCore

struct PathsTests {
    @Test func everyPathIsUnderTheHomeDirectory() {
        let paths = WardenrunPaths(home: "/Users/someone")
        #expect(paths.configDirectory == "/Users/someone/.config/wardenrun")
        #expect(paths.bwAppData == "/Users/someone/.config/wardenrun/bw")
        #expect(paths.lockFile == "/Users/someone/.config/wardenrun/bw.lock")
        #expect(paths.stateDirectory == "/Users/someone/.config/wardenrun/state")
        #expect(paths.installedBw == "/Users/someone/.config/wardenrun/bin/bw")
        #expect(paths.auditLog == "/Users/someone/Library/Logs/wardenrun/audit.jsonl")
    }

    @Test func aTrailingSlashOnTheHomeDoesNotDoubleUp() {
        #expect(WardenrunPaths(home: "/Users/someone/").configDirectory == "/Users/someone/.config/wardenrun")
    }
}

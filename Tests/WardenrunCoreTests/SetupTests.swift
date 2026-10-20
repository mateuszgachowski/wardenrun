import Foundation
import Testing
@testable import WardenrunCore

private let teamID = "LTZ2PFU5D6"

private func makeConfig(server: String = "https://vault.example", email: String = "it-user@example.test",
                        org: String = "org-1", collections: [String] = ["col-a"], password: String = "master-pass-KNOWN-9",
                        bw: String = "/opt/wardenrun/bin/bw") throws -> ProtectedConfig {
    try ProtectedConfig(serverURL: try #require(URL(string: server)), accountEmail: email, organizationID: org,
                        collectionIDs: collections, masterPassword: SecretBuffer(copying: Array(password.utf8)),
                        bwPin: .signedRelease(teamID: teamID, path: bw))
}

struct SetupApprovalTextTests {
    @Test func approvalTextShowsOldAndNewValuesAndNeverThePassword() throws {
        let old = try makeConfig(server: "https://old.example", email: "old@example.test", password: "OLD-SECRET-PW")
        let new = try makeConfig(server: "https://new.example", email: "new@example.test", password: "NEW-SECRET-PW")
        let text = try Setup.approvalText(old: old, new: new)
        for shown in ["https://new.example", "https://old.example", "new@example.test", "old@example.test", "org-1", "col-a", teamID] {
            #expect(text.contains(shown), "\(shown) missing in: \(text)")
        }
        #expect(!text.contains("SECRET-PW"))
        #expect(text.count <= 400)
    }

    @Test func aFirstSetupSaysThereIsNoPreviousValue() throws {
        let text = try Setup.approvalText(old: nil, new: try makeConfig())
        #expect(text.lowercased().contains("first setup"))
        #expect(text.contains("no previous value"))
        #expect(!text.contains("was:"))
    }

    @Test func anUnchangedValueIsMarkedUnchangedNotRepeated() throws {
        let text = try Setup.approvalText(old: try makeConfig(), new: try makeConfig(server: "https://new.example"))
        #expect(text.contains("unchanged"))
        #expect(text.contains("was: https://vault.example"))
    }

    @Test func approvalTextOverTheBudgetIsRefusedNotTruncated() throws {
        let many = (0..<12).map { "00000000-0000-0000-0000-0000000000\(String(format: "%02d", $0))" }
        let big = try makeConfig(collections: many)
        #expect(throws: SetupError.approvalTextTooLong) { _ = try Setup.approvalText(old: nil, new: big) }
    }

    @Test func theTextBudgetIs400Characters() throws {
        #expect(Setup.approvalBudget == 400)
    }
}

struct SetupBwTests {
    /// A directory with a fake `bw`: it records every call (argv, environment, what arrives on
    /// descriptor 3) and fails or waits when told to by files in `rec`.
    private struct Rig {
        let dir: String
        let rec: String
        let bw: String
        let lockPath: String
        let appData: String

        init(dir: String) {
            self.dir = dir
            rec = dir + "/rec"
            try? FileManager.default.createDirectory(atPath: rec, withIntermediateDirectories: true)
            bw = writeFile(dir + "/bin/bw", """
            #!/bin/sh
            # The child's PATH is only the pinned bw directory, so every tool is named in full.
            REC='\(dir)/rec'
            n=$(/bin/cat "$REC/n" 2>/dev/null || echo 0)
            n=$((n+1))
            echo $n > "$REC/n"
            printf '%s\\n' "$@" > "$REC/argv.$n"
            /usr/bin/env > "$REC/env.$n"
            case "$1" in
              logout) exit 1 ;;
              config) [ -f "$REC/failConfig" ] && exit 1 ;;
              login)
                /bin/cat <&3 > "$REC/fd3.$n"
                /usr/bin/touch "$REC/started"
                while [ -f "$REC/hold" ]; do /bin/sleep 0.05; done
                if [ -f "$REC/failLogin" ]; then echo "LEAKY-BW-OUTPUT $(/bin/cat "$REC/fd3.$n")" ; echo "LEAKY-STDERR" >&2; exit 1; fi
                ;;
            esac
            exit 0

            """)
            lockPath = dir + "/state/bw.lock"
            appData = dir + "/appdata"
        }

        func calls() -> [[String]] {
            let count = Int((try? String(contentsOfFile: rec + "/n", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "0") ?? 0
            return (0..<count).map { index in
                let text = (try? String(contentsOfFile: rec + "/argv.\(index + 1)", encoding: .utf8)) ?? ""
                return text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
            }
        }

        func file(_ name: String) -> String { (try? String(contentsOfFile: rec + "/" + name, encoding: .utf8)) ?? "" }
    }

    private struct Accept: BwSignatureChecker {
        func check(path: String, teamID: String) throws {}
    }

    private func withRig(_ body: (Rig) throws -> Void) throws {
        try withTempDirectory { raw in try body(Rig(dir: realPath(raw))) }
    }

    private func config(_ rig: Rig, password: String = "master-pass-KNOWN-9") throws -> ProtectedConfig {
        try makeConfig(password: password, bw: rig.bw)
    }

    @Test func configureBwRunsConfigThenLoginWithThePasswordOnAnInheritedPipeAndNotInArgvOrEnv() throws {
        try withRig { rig in
            try Setup.configureBw(config: try config(rig), appDataDir: rig.appData, home: rig.dir + "/home",
                                  lockPath: rig.lockPath, signature: Accept(), timeouts: .default)
            #expect(rig.calls() == [["logout", "--quiet", "--nointeraction"],
                                    ["config", "server", "https://vault.example", "--nointeraction"],
                                    ["login", "it-user@example.test", "--passwordfile", "/dev/fd/3", "--quiet", "--nointeraction"]])
            #expect(rig.file("fd3.3") == "master-pass-KNOWN-9\n")
            for index in 1...3 {
                #expect(!rig.file("argv.\(index)").contains("KNOWN"), "argv \(index)")
                let env = rig.file("env.\(index)")
                #expect(!env.contains("KNOWN"), "env \(index)")
                #expect(!env.contains("BW_SESSION") && !env.contains("BW_PASSWORD"))
                #expect(env.contains("BITWARDENCLI_APPDATA_DIR=" + rig.appData))
            }
        }
    }

    @Test func aFailingLogoutIsIgnoredBecauseThereMayBeNothingToLogOutOf() throws {
        try withRig { rig in
            // The fake's logout always exits 1; configureBw above succeeded anyway.
            try Setup.configureBw(config: try config(rig), appDataDir: rig.appData, home: rig.dir + "/home",
                                  lockPath: rig.lockPath, signature: Accept(), timeouts: .default)
        }
    }

    @Test func loginFailureMapsToBwFailedWithoutBwOutput() throws {
        try withRig { rig in
            try Data().write(to: URL(fileURLWithPath: rig.rec + "/failLogin"))
            do {
                try Setup.configureBw(config: try config(rig), appDataDir: rig.appData, home: rig.dir + "/home",
                                      lockPath: rig.lockPath, signature: Accept(), timeouts: .default)
                Issue.record("a failing login must throw")
            } catch let error as SetupError {
                #expect(error == .bwFailed(step: "login"))
                #expect(!"\(error)".contains("LEAKY") && !error.message.contains("LEAKY") && !error.message.contains("KNOWN"))
            }
        }
    }

    @Test func aFailingConfigServerStopsBeforeLogin() throws {
        try withRig { rig in
            try Data().write(to: URL(fileURLWithPath: rig.rec + "/failConfig"))
            #expect(throws: SetupError.bwFailed(step: "config server")) {
                try Setup.configureBw(config: try config(rig), appDataDir: rig.appData, home: rig.dir + "/home",
                                      lockPath: rig.lockPath, signature: Accept(), timeouts: .default)
            }
            #expect(rig.calls().map { $0[0] } == ["logout", "config"], "login must not run after a failed config")
        }
    }

    @Test func aSignatureThatDoesNotMatchStopsBeforeBwRuns() throws {
        struct Refuse: BwSignatureChecker { func check(path: String, teamID: String) throws { throw BwError.signatureMismatch } }
        try withRig { rig in
            #expect(throws: SetupError.bwFailed(step: "pin")) {
                try Setup.configureBw(config: try config(rig), appDataDir: rig.appData, home: rig.dir + "/home",
                                      lockPath: rig.lockPath, signature: Refuse(), timeouts: .default)
            }
            #expect(rig.calls().isEmpty)
        }
    }

    @Test func theLockIsHeldDuringConfigureAndReleasedAfterwards() throws {
        try withRig { rig in
            try Data().write(to: URL(fileURLWithPath: rig.rec + "/hold"))
            let finished = Box<Result<Void, Error>?>(nil)
            let setup = Thread { [self] in
                finished.value = Result { try Setup.configureBw(config: try config(rig), appDataDir: rig.appData,
                                                               home: rig.dir + "/home", lockPath: rig.lockPath,
                                                               signature: Accept(), timeouts: .default) }
            }
            setup.start()
            let deadline = Date().addingTimeInterval(20)
            while !FileManager.default.fileExists(atPath: rig.rec + "/started") && Date() < deadline { usleep(10_000) }
            #expect(FileManager.default.fileExists(atPath: rig.rec + "/started"), "login never started")
            #expect(throws: BwError.lockBusy) { _ = try BwLock.acquire(path: rig.lockPath, timeout: 0.1) }
            try FileManager.default.removeItem(atPath: rig.rec + "/hold")
            while finished.value == nil && Date() < deadline { usleep(10_000) }
            _ = try #require(finished.value).get()
            let lock = try BwLock.acquire(path: rig.lockPath, timeout: 1)
            lock.release()
        }
    }

    @Test func verifyUsesUnlockAndLockOnly() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bin/bw")
            let fake = FakeServe()
            fake.password = "master-pass-KNOWN-9"
            let vault = BwVault(config: try makeConfig(bw: bw), appDataDir: dir + "/appdata", home: dir + "/home",
                                lockPath: dir + "/state/bw.lock", signature: Accept(), launcherOverride: fake)
            try Setup.verify(vault: vault)
            #expect(fake.log == ["GET /status", "POST /unlock", "POST /lock"])
        }
    }

    @Test func aWrongPasswordFailsVerifyWithAFixedSummary() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let bw = writeFile(dir + "/bin/bw")
            let fake = FakeServe()
            fake.password = "some-other-password"
            let vault = BwVault(config: try makeConfig(bw: bw), appDataDir: dir + "/appdata", home: dir + "/home",
                                lockPath: dir + "/state/bw.lock", signature: Accept(), launcherOverride: fake)
            do {
                try Setup.verify(vault: vault)
                Issue.record("a wrong password must fail verify")
            } catch let error as SetupError {
                #expect(error == .verifyFailed(summary: "the vault could not be unlocked"))
                #expect(!error.message.contains("KNOWN"))
            }
        }
    }
}

struct SetupInputTests {
    @Test func setupRefusesWithoutATTY() {
        #expect(throws: SetupError.notInteractive) { try Setup.requireInteractive(false) }
        #expect(throws: Never.self) { try Setup.requireInteractive(true) }
    }

    @Test func setupWithHTTPServerChangesNothing() throws {
        let input = SetupInput(serverURL: "http://vault.example", email: "a@b.example", organizationID: "o", collectionIDs: ["c"],
                               masterPassword: SecretBuffer(copying: Array("pw-123456".utf8)),
                               bwPin: .signedRelease(teamID: teamID, path: "/opt/bw"), nodeExtraCACerts: nil, httpsProxy: nil)
        #expect(throws: SetupError.invalid(field: "server")) { _ = try Setup.makeConfig(input) }
    }

    @Test func eachInvalidFieldIsNamedNeverItsValue() throws {
        func input(server: String = "https://vault.example", email: String = "a@b.example", org: String = "org",
                   collections: [String] = ["col"], password: String = "pw-123456") -> SetupInput {
            SetupInput(serverURL: server, email: email, organizationID: org, collectionIDs: collections,
                       masterPassword: SecretBuffer(copying: Array(password.utf8)),
                       bwPin: .signedRelease(teamID: teamID, path: "/opt/bw"), nodeExtraCACerts: nil, httpsProxy: nil)
        }
        #expect(throws: SetupError.invalid(field: "email")) { _ = try Setup.makeConfig(input(email: "")) }
        #expect(throws: SetupError.invalid(field: "organization")) { _ = try Setup.makeConfig(input(org: "bad org!")) }
        #expect(throws: SetupError.invalid(field: "collections")) { _ = try Setup.makeConfig(input(collections: [])) }
        #expect(throws: SetupError.invalid(field: "collections")) { _ = try Setup.makeConfig(input(collections: ["fine", "not fine"])) }
        #expect(throws: SetupError.invalid(field: "password")) { _ = try Setup.makeConfig(input(password: "")) }
        #expect(throws: SetupError.invalid(field: "password"), "bw would read only the first line") {
            _ = try Setup.makeConfig(input(password: "first-line\nsecond"))
        }
        #expect(throws: SetupError.invalid(field: "password")) { _ = try Setup.makeConfig(input(password: "with-cr\rtail")) }
        let ok = try Setup.makeConfig(input())
        #expect(ok.organizationID == "org")
    }
}

struct SetupInstallTests {
    private final class Recorder: BwSignatureChecker, @unchecked Sendable {
        private let lock = NSLock()
        private var seen: [String] = []
        var accept = true
        /// 1-based number of the one call that is refused, when only that one should fail.
        var refuseCall: Int?
        var calls: [String] { lock.lock(); defer { lock.unlock() }; return seen }
        func check(path: String, teamID: String) throws {
            lock.lock(); seen.append(path); let number = seen.count; lock.unlock()
            if !accept || number == refuseCall { throw BwError.signatureMismatch }
        }
    }

    @Test func copiedBwIsPinnedAtItsNewPathAndRechecked() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let source = writeFile(dir + "/download/bw", "#!/bin/sh\necho original\n")
            let destination = dir + "/home/.config/wardenrun/bin/bw"
            let checker = Recorder()
            let pin = try Setup.installBw(from: source, teamID: teamID, to: destination, signature: checker)
            #expect(pin == .signedRelease(teamID: teamID, path: destination))
            #expect(try String(contentsOfFile: destination, encoding: .utf8) == "#!/bin/sh\necho original\n")
            #expect(permissionBits(of: destination) == 0o700)
            #expect(permissionBits(of: dir + "/home/.config/wardenrun/bin") == 0o700)
            #expect(checker.calls.count == 2)
            #expect(checker.calls.first != destination, "the copy is checked before it takes the final name")
            #expect(checker.calls.last == destination, "and the file at its final name is checked again")
            #expect(try FileManager.default.contentsOfDirectory(atPath: dir + "/home/.config/wardenrun/bin") == ["bw"])
        }
    }

    @Test func aCopyThatFailsTheSignatureLeavesNothingAndKeepsTheOldFile() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let source = writeFile(dir + "/download/bw", "new")
            let destination = dir + "/bin/bw"
            _ = writeFile(destination, "old")
            let checker = Recorder()
            checker.accept = false
            #expect(throws: SetupError.installFailed(reason: "the copy does not carry the expected signature")) {
                _ = try Setup.installBw(from: source, teamID: teamID, to: destination, signature: checker)
            }
            let kept = try String(contentsOfFile: destination, encoding: .utf8)
            let listing = try FileManager.default.contentsOfDirectory(atPath: dir + "/bin")
            #expect(kept == "old")
            #expect(listing == ["bw"])
        }
    }

    @Test func aFileThatFailsTheCheckAtItsFinalNameIsRemoved() {
        withTempDirectory { raw in
            let dir = realPath(raw)
            let source = writeFile(dir + "/download/bw", "new")
            let destination = dir + "/bin/bw"
            let checker = Recorder()
            checker.refuseCall = 2
            #expect(throws: SetupError.installFailed(reason: "the installed file does not carry the expected signature")) {
                _ = try Setup.installBw(from: source, teamID: teamID, to: destination, signature: checker)
            }
            #expect(!FileManager.default.fileExists(atPath: destination), "a file that failed the check must not stay executable")
        }
    }

    @Test func anExistingLooseInstallDirectoryIsTightenedTo0700() throws {
        try withTempDirectory { raw in
            let dir = realPath(raw)
            let source = writeFile(dir + "/download/bw", "new")
            try FileManager.default.createDirectory(atPath: dir + "/bin", withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o755])
            chmod(dir + "/bin", 0o755)
            _ = try Setup.installBw(from: source, teamID: teamID, to: dir + "/bin/bw", signature: Recorder())
            #expect(permissionBits(of: dir + "/bin") == 0o700)
        }
    }

    @Test func aMissingSourceIsRefused() {
        #expect(throws: SetupError.installFailed(reason: "the bw file to copy is missing")) {
            _ = try Setup.installBw(from: "/nonexistent/bw", teamID: teamID, to: "/tmp/never/bw", signature: Recorder())
        }
    }
}

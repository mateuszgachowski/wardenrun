import Foundation
import Testing
@testable import WardenrunCore

struct InjectionPlanTests {
    private func item(_ json: String, name: String = "it-github") -> BwFetchedItem {
        BwFetchedItem(itemJSON: SecretBuffer(copying: Array(json.utf8)), id: "item-1", name: name)
    }

    private let full = """
    {"login":{"username":"agent-user","password":"P4SSWORD-VALUE","totp":null,"uris":[]},
     "notes":"NOTE-VALUE-123",
     "fields":[{"name":"env:API_TOKEN","value":"TOKEN-VALUE-1","type":1},
               {"name":"env:OTHER","value":"OTHER-VALUE-22","type":1},
               {"name":"plain","value":"PLAIN-VALUE-3","type":0}]}
    """

    private func options(env: [(String, String)] = [], files: [(String, String)] = [], stdin: String? = nil) -> RunOptions {
        RunOptions(item: "it-github", env: env.map { FieldBinding(name: $0.0, field: $0.1) },
                   files: files.map { FieldBinding(name: $0.0, field: $0.1) }, stdin: stdin, command: ["true"])
    }

    /// The `RunError` a body throws, or nil.
    private func runError(_ body: () throws -> Void) -> RunError? {
        do { try body() } catch let error as RunError { return error } catch {}
        return nil
    }

    private func text(_ buffer: SecretBuffer?) -> String? {
        buffer.map { $0.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }
    }

    @Test func noFlagsInjectsTheItemsEnvColonFields() throws {
        let plan = try InjectionPlan.make(options: options(), item: item(full))
        #expect(Set(plan.environment.keys) == ["API_TOKEN", "OTHER"])
        #expect(text(plan.environment["API_TOKEN"]) == "TOKEN-VALUE-1")
        #expect(text(plan.environment["OTHER"]) == "OTHER-VALUE-22")
        #expect(plan.files.isEmpty)
        #expect(plan.stdin == nil)
    }

    @Test func envFlagBindsAVariableToAField() throws {
        let plan = try InjectionPlan.make(options: options(env: [("GH_TOKEN", "password"), ("WHO", "username"), ("N", "notes"), ("C", "plain")]), item: item(full))
        #expect(Set(plan.environment.keys) == ["GH_TOKEN", "WHO", "N", "C"], "with flags, the env: fields are NOT added on top")
        #expect(text(plan.environment["GH_TOKEN"]) == "P4SSWORD-VALUE")
        #expect(text(plan.environment["WHO"]) == "agent-user")
        #expect(text(plan.environment["N"]) == "NOTE-VALUE-123")
        #expect(text(plan.environment["C"]) == "PLAIN-VALUE-3")
    }

    @Test func aMissingFieldFailsWithItsNameAndNoValue() throws {
        let error = runError { _ = try InjectionPlan.make(options: options(env: [("X", "nothere")]), item: item(full)) }
        #expect(error == .fieldMissing("nothere"))
        #expect(error?.message.contains("nothere") == true)
        #expect(error?.message.contains("VALUE") == false)
        // a standard field that is empty in this item is missing too
        #expect(throws: RunError.fieldMissing("uri")) {
            _ = try InjectionPlan.make(options: options(env: [("X", "uri")]), item: item(full))
        }
    }

    @Test func anEmptyValueCountsAsMissing() throws {
        let empty = #"{"login":{"password":""},"fields":[{"name":"env:E","value":""}]}"#
        #expect(throws: RunError.fieldMissing("password")) { _ = try InjectionPlan.make(options: options(env: [("X", "password")]), item: item(empty)) }
        #expect(throws: RunError.fieldMissing("env:E")) { _ = try InjectionPlan.make(options: options(), item: item(empty)) }
    }

    @Test func theSameVariableTwiceIsRefused() throws {
        #expect(throws: RunError.duplicateVariable("A")) {
            _ = try InjectionPlan.make(options: options(env: [("A", "password"), ("A", "username")]), item: item(full))
        }
        #expect(throws: RunError.duplicateVariable("A")) {
            _ = try InjectionPlan.make(options: options(env: [("A", "password")], files: [("A", "notes")]), item: item(full))
        }
        let twice = """
        {"fields":[{"name":"env:SAME","value":"first-value-1"},{"name":"env:SAME","value":"second-value"}]}
        """
        #expect(throws: RunError.duplicateVariable("SAME")) { _ = try InjectionPlan.make(options: options(), item: item(twice)) }
    }

    @Test func loaderVariablesAreRefused() throws {
        for name in ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "1BAD", "has space", "", "A=B"] {
            #expect(throws: RunError.invalidVariable(name), "\(name)") {
                _ = try InjectionPlan.make(options: options(env: [(name, "password")]), item: item(full))
            }
        }
        let evil = """
        {"fields":[{"name":"env:DYLD_INSERT_LIBRARIES","value":"/tmp/evil.dylib"}]}
        """
        #expect(throws: RunError.invalidVariable("DYLD_INSERT_LIBRARIES")) { _ = try InjectionPlan.make(options: options(), item: item(evil)) }
        #expect(throws: RunError.invalidVariable("PATH2=")) {
            _ = try InjectionPlan.make(options: options(files: [("PATH2=", "password")]), item: item(full))
        }
    }

    @Test func anItemWithoutEnvFieldsAndNoFlagsIsRefused() throws {
        let bare = #"{"login":{"password":"P4SSWORD-VALUE"},"fields":[{"name":"plain","value":"x-value-12"}]}"#
        #expect(throws: RunError.noInjection) { _ = try InjectionPlan.make(options: options(), item: item(bare)) }
        #expect(throws: RunError.noInjection) { _ = try InjectionPlan.make(options: options(), item: item(#"{"login":{}}"#)) }
    }

    @Test func stdinTakesOneField() throws {
        let plan = try InjectionPlan.make(options: options(stdin: "password"), item: item(full))
        #expect(text(plan.stdin) == "P4SSWORD-VALUE")
        #expect(plan.environment.isEmpty, "only stdin was asked for, so the env: fields stay home")
        #expect(throws: RunError.fieldMissing("nothere")) { _ = try InjectionPlan.make(options: options(stdin: "nothere"), item: item(full)) }
    }

    @Test func fileBindingsCarryTheValueAndTheVariableForThePath() throws {
        let plan = try InjectionPlan.make(options: options(files: [("KEY_FILE", "notes")]), item: item(full))
        #expect(plan.files.count == 1)
        #expect(plan.files.first?.variable == "KEY_FILE")
        #expect(text(plan.files.first?.buffer) == "NOTE-VALUE-123")
        #expect(plan.environment.isEmpty)
    }

    @Test func totpIsNotSupportedAndNamedAsSuch() throws {
        #expect(throws: BwError.unsupportedField("totp")) {
            _ = try InjectionPlan.make(options: options(env: [("T", "totp")]), item: item(full))
        }
    }

    @Test func aValueWithANulByteCannotBeAnEnvironmentVariable() throws {
        let nul = #"{"fields":[{"name":"env:BAD","value":"abc\u0000def-123"},{"name":"env:GOOD","value":"fine-value-1"}]}"#
        let error = runError { _ = try InjectionPlan.make(options: options(), item: item(nul)) }
        #expect(error == .nulInEnvironmentValue("BAD"))
        // the same value is fine as a file or on stdin
        let viaFile = try InjectionPlan.make(options: options(files: [("F", "env:BAD")]), item: item(nul))
        #expect(viaFile.files.count == 1)
        let viaStdin = try InjectionPlan.make(options: options(stdin: "env:BAD"), item: item(nul))
        #expect(viaStdin.stdin?.count == 11)
    }

    @Test func maskSecretsCarryTheItemNameNotTheFieldNameAndEveryInjectedValue() throws {
        let plan = try InjectionPlan.make(options: options(env: [("A", "password")], files: [("F", "notes")], stdin: "username"), item: item(full, name: "my item"))
        let secrets = plan.maskSecrets
        #expect(secrets.count == 3)
        #expect(secrets.allSatisfy { $0.name == "my item" })
        let values = Set(secrets.map { String(decoding: $0.value, as: UTF8.self) })
        #expect(values == ["P4SSWORD-VALUE", "NOTE-VALUE-123", "agent-user"])
    }

    @Test func wipeZeroesEveryBuffer() throws {
        let plan = try InjectionPlan.make(options: options(env: [("A", "password")], files: [("F", "notes")], stdin: "username"), item: item(full))
        let all = Array(plan.environment.values) + plan.files.map(\.buffer) + [plan.stdin].compactMap { $0 }
        #expect(all.count == 3)
        #expect(all.allSatisfy { !$0.isWiped })
        plan.wipe()
        #expect(all.allSatisfy { $0.isWiped })
        #expect(plan.maskSecrets.isEmpty)
    }

    @Test func messagesNameTheFieldOrVariableAndEscapeIt() {
        #expect(RunError.fieldMissing("a\nb").message.contains("a\\nb"))
        #expect(!RunError.invalidVariable("x\u{202E}y").message.unicodeScalars.contains { $0.value == 0x202E })
        #expect(RunError.noInjection.message.contains("env:"))
        #expect(RunError.duplicateVariable("A").message.contains("A"))
        #expect(!RunError.tempFile.message.isEmpty)
        #expect(RunError.nulInEnvironmentValue("BAD").message.contains("BAD"))
    }
}

struct SecretFilesTests {
    private func buffer(_ text: String) -> SecretBuffer { SecretBuffer(copying: Array(text.utf8)) }

    @Test func secretFilesAre0600InA0700DirectoryAndAreRemoved() throws {
        try withTempDirectory { parent in
            try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true)
            let files = SecretFiles(parent: parent)
            let paths = try files.write([("A_FILE", buffer("first-secret")), ("B_FILE", buffer("second-secret"))])
            #expect(Set(paths.keys) == ["A_FILE", "B_FILE"])
            let a = try #require(paths["A_FILE"]), b = try #require(paths["B_FILE"])
            #expect(a != b)
            let firstText = try String(contentsOfFile: a, encoding: .utf8)
            let secondText = try String(contentsOfFile: b, encoding: .utf8)
            #expect(firstText == "first-secret")
            #expect(secondText == "second-secret")
            #expect(permissionBits(of: a) == 0o600)
            #expect(permissionBits(of: b) == 0o600)
            let directory = (a as NSString).deletingLastPathComponent
            #expect(directory == (b as NSString).deletingLastPathComponent)
            #expect(directory.hasPrefix(parent + "/"))
            #expect(permissionBits(of: directory) == 0o700)
            files.removeAll()
            #expect(!FileManager.default.fileExists(atPath: a))
            #expect(!FileManager.default.fileExists(atPath: directory))
        }
    }

    @Test func aFileHoldsExactlyTheBytesIncludingNulAndNoNewline() throws {
        try withTempDirectory { parent in
            let files = SecretFiles(parent: parent)
            let bytes: [UInt8] = [0x61, 0x00, 0xFF, 0x0A, 0x62]
            let paths = try files.write([("F", SecretBuffer(copying: bytes))])
            let path = try #require(paths["F"])
            let written = try Data(contentsOf: URL(fileURLWithPath: path))
            #expect(written == Data(bytes))
            files.removeAll()
        }
    }

    @Test func removeAllIsIdempotentAndRemovesEvenAfterAFailedWrite() throws {
        try withTempDirectory { parent in
            let files = SecretFiles(parent: parent)
            files.removeAll()                                    // nothing written yet: harmless
            let paths = try files.write([("A", buffer("one-secret"))])
            let first = try #require(paths["A"])
            // a second write on the same object is refused, the first file is still removed
            #expect(throws: RunError.tempFile) { _ = try files.write([("B", buffer("two-secret"))]) }
            files.removeAll()
            files.removeAll()
            #expect(!FileManager.default.fileExists(atPath: first))
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: parent)
            #expect(leftovers.isEmpty)
        }
    }

    @Test func aParentThatDoesNotExistIsATempFileErrorAndLeavesNothing() throws {
        try withTempDirectory { parent in
            let files = SecretFiles(parent: parent + "/missing/deeper")
            #expect(throws: RunError.tempFile) { _ = try files.write([("A", buffer("one-secret"))]) }
            files.removeAll()
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: parent)
            #expect(leftovers.isEmpty)
        }
    }

    @Test func aWriteThatFailsHalfWayStillRemovesTheFilesAlreadyMade() throws {
        try withTempDirectory { parent in
            let files = SecretFiles(parent: parent)
            // two variables with the same name collide on the second file
            #expect(throws: RunError.tempFile) {
                _ = try files.write([("A", buffer("one-secret")), ("A", buffer("two-secret"))])
            }
            files.removeAll()
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: parent)
            #expect(leftovers.isEmpty)
        }
    }

    @Test func aVariableNameThatIsNotAPlainNameIsRefusedAndNothingLeavesTheDirectory() throws {
        try withTempDirectory { parent in
            for name in ["../escape", "a/b", "", ".", "..", "with space"] {
                let files = SecretFiles(parent: parent)
                #expect(throws: RunError.tempFile, "\(name)") { _ = try files.write([(name, buffer("some-secret"))]) }
                files.removeAll()
            }
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: parent)
            #expect(leftovers.isEmpty, "\(leftovers)")
        }
    }

    @Test func theSecretIsNeverInTheFileName() throws {
        try withTempDirectory { parent in
            let files = SecretFiles(parent: parent)
            let paths = try files.write([("A", buffer("needle-in-name"))])
            let path = try #require(paths["A"])
            #expect(!path.contains("needle"))
            files.removeAll()
        }
    }
}

import Foundation
import Testing
@testable import WardenrunCore

struct CommandLineTests {
    private func parse(_ arguments: String...) throws -> Command { try CommandParser.parse(arguments) }

    // MARK: simple commands

    @Test func noArgumentsShowHelp() throws {
        #expect(try CommandParser.parse([]) == .help)
    }

    @Test(arguments: [["help"], ["--help"], ["-h"]])
    func helpNeedsNoOtherArguments(arguments: [String]) throws {
        #expect(try CommandParser.parse(arguments) == .help)
        #expect(throws: UsageError.unexpectedArgument("x")) { try CommandParser.parse(arguments + ["x"]) }
    }

    @Test(arguments: [["version"], ["--version"], ["-V"]])
    func versionNeedsNoOtherArguments(arguments: [String]) throws {
        #expect(try CommandParser.parse(arguments) == .version)
        #expect(throws: UsageError.unexpectedArgument("x")) { try CommandParser.parse(arguments + ["x"]) }
    }

    @Test func doctorTakesNoArguments() throws {
        #expect(try parse("doctor") == .doctor)
        #expect(throws: UsageError.unexpectedArgument("--json")) { try parse("doctor", "--json") }
    }

    @Test func anUnknownCommandIsRefused() {
        #expect(throws: UsageError.unknownCommand("frobnicate")) { try parse("frobnicate") }
    }

    // MARK: setup

    @Test func setupWithAndWithoutABwPath() throws {
        #expect(try parse("setup") == .setup(SetupOptions(bwPath: nil)))
        #expect(try parse("setup", "--bw", "/opt/bw/bw") == .setup(SetupOptions(bwPath: "/opt/bw/bw")))
        #expect(throws: UsageError.missingValue(option: "--bw")) { try parse("setup", "--bw") }
        #expect(throws: UsageError.duplicateOption("--bw")) { try parse("setup", "--bw", "/a", "--bw", "/b") }
        #expect(throws: UsageError.unexpectedArgument("extra")) { try parse("setup", "extra") }
    }

    // MARK: run

    @Test func runWithEveryOption() throws {
        let command = try parse("run", "my-item", "--env", "A=password", "--file", "B=notes", "--stdin", "username",
                                "--", "cmd", "a", "b")
        #expect(command == .run(RunOptions(item: "my-item", env: [FieldBinding(name: "A", field: "password")],
                                           files: [FieldBinding(name: "B", field: "notes")], stdin: "username",
                                           command: ["cmd", "a", "b"])))
    }

    @Test func runWithJustACommand() throws {
        #expect(try parse("run", "item", "--", "ls") == .run(RunOptions(item: "item", env: [], files: [], stdin: nil, command: ["ls"])))
    }

    @Test func optionsMayComeBeforeTheItemToo() throws {
        let command = try parse("run", "--env", "A=password", "item", "--", "ls")
        #expect(command == .run(RunOptions(item: "item", env: [FieldBinding(name: "A", field: "password")], files: [],
                                           stdin: nil, command: ["ls"])))
    }

    @Test func theDoubleDashIsRequiredAndFlagsAfterItBelongToTheCommand() throws {
        #expect(throws: UsageError.missingCommand) { try parse("run", "item") }
        #expect(throws: UsageError.missingCommand) { try parse("run", "item", "--") }
        #expect(throws: UsageError.missingCommand) { try parse("run", "item", "--env", "A=password") }
        let command = try parse("run", "item", "--", "curl", "--env", "X=y", "--stdin", "--")
        #expect(command == .run(RunOptions(item: "item", env: [], files: [], stdin: nil,
                                           command: ["curl", "--env", "X=y", "--stdin", "--"])))
    }

    @Test func runNeedsAnItem() {
        #expect(throws: UsageError.missingItem) { try parse("run") }
        #expect(throws: UsageError.missingItem) { try parse("run", "--", "ls") }
    }

    @Test func repeatedEnvAndFileFlagsAccumulateInOrder() throws {
        let command = try parse("run", "item", "--env", "A=password", "--env", "B=username", "--file", "C=notes",
                                "--file", "D=totp", "--", "x")
        guard case .run(let options) = command else { Issue.record("not a run"); return }
        #expect(options.env == [FieldBinding(name: "A", field: "password"), FieldBinding(name: "B", field: "username")])
        #expect(options.files == [FieldBinding(name: "C", field: "notes"), FieldBinding(name: "D", field: "totp")])
    }

    @Test func aFieldMayContainEqualsSignsAndSpaces() throws {
        let command = try parse("run", "item", "--env", "TOKEN=my field=1", "--", "x")
        guard case .run(let options) = command else { Issue.record("not a run"); return }
        #expect(options.env == [FieldBinding(name: "TOKEN", field: "my field=1")])
    }

    @Test(arguments: ["=password", "A=", "A", "", "=", "1A=password", "A B=password", "A-B=password"])
    func badBindingsAreRefused(binding: String) {
        #expect(throws: UsageError.badBinding(option: "--env")) { try parse("run", "item", "--env", binding, "--", "x") }
        #expect(throws: UsageError.badBinding(option: "--file")) { try parse("run", "item", "--file", binding, "--", "x") }
    }

    @Test func forbiddenEnvironmentNamesAreRefusedAtParseTime() {
        #expect(throws: UsageError.badBinding(option: "--env")) { try parse("run", "item", "--env", "LD_PRELOAD=password", "--", "x") }
        #expect(throws: UsageError.badBinding(option: "--file")) { try parse("run", "item", "--file", "DYLD_INSERT_LIBRARIES=password", "--", "x") }
    }

    @Test func theSameNameTwiceIsRefused() {
        #expect(throws: UsageError.duplicateName("A")) { try parse("run", "item", "--env", "A=password", "--env", "A=username", "--", "x") }
        #expect(throws: UsageError.duplicateName("A")) { try parse("run", "item", "--env", "A=password", "--file", "A=notes", "--", "x") }
    }

    @Test func stdinTakesOneFieldOnlyOnce() {
        #expect(throws: UsageError.duplicateOption("--stdin")) { try parse("run", "item", "--stdin", "password", "--stdin", "notes", "--", "x") }
        #expect(throws: UsageError.missingValue(option: "--stdin")) { try parse("run", "item", "--stdin") }
        #expect(throws: UsageError.badValue(option: "--stdin")) { try parse("run", "item", "--stdin", "", "--", "x") }
    }

    @Test func aSecondPositionalBeforeTheDoubleDashIsRefused() {
        #expect(throws: UsageError.unexpectedArgument("other")) { try parse("run", "item", "other", "--", "x") }
    }

    @Test func anOptionWithoutItsValueIsRefused() {
        #expect(throws: UsageError.missingValue(option: "--env")) { try parse("run", "item", "--env") }
        #expect(throws: UsageError.badBinding(option: "--env")) { try parse("run", "item", "--env", "--", "x") }
    }

    @Test func unknownOptionsAreRefusedWithoutEchoingControlCharacters() {
        let evil = "--x\u{1B}[31mred\u{07}\n"
        do {
            _ = try CommandParser.parse(["run", "item", evil, "--", "x"])
            Issue.record("must be refused")
        } catch let error as UsageError {
            let text = error.message
            #expect(!text.unicodeScalars.contains { $0.properties.generalCategory == .control }, "\(text.debugDescription)")
            #expect(text.contains("--x"))
            #expect(error == UsageError.unknownOption(UsageError.escaped(evil)))
        } catch { Issue.record("wrong error \(error)") }
    }

    @Test func escapedLimitsLengthAndHidesBidiAndControlCharacters() {
        #expect(UsageError.escaped("abc") == "abc")
        #expect(UsageError.escaped("a\u{1B}b") == "a<U+001B>b")
        #expect(UsageError.escaped("a\u{202E}b") == "a<U+202E>b")
        #expect(UsageError.escaped("zażółć") == "zażółć")
        let long = UsageError.escaped(String(repeating: "x", count: 100))
        #expect(long.count == 41 && long.hasSuffix("…"))
    }

    @Test func itemNamesWithControlCharactersAreRefused() {
        #expect(throws: UsageError.badName) { try parse("run", "ite\u{0}m", "--", "x") }
        #expect(throws: UsageError.badName) { try parse("run", "it\nem", "--", "x") }
    }

    // MARK: new

    @Test func newWithDefaults() throws {
        #expect(try parse("new", "staging-db") == .new(NewOptions(name: "staging-db", username: nil, uri: nil, env: nil,
                                                                  length: 32, charset: .alnum)))
    }

    @Test func newWithEveryOption() throws {
        let command = try parse("new", "staging-db", "--username", "admin", "--uri", "https://db.example", "--env", "DB_PASSWORD",
                                "--length", "48", "--charset", "full")
        #expect(command == .new(NewOptions(name: "staging-db", username: "admin", uri: "https://db.example", env: "DB_PASSWORD",
                                           length: 48, charset: .full)))
    }

    @Test(arguments: ["15", "129", "0", "-1", "abc", "", "32.5", "99999999999999999999"])
    func lengthMustBeBetween16And128(length: String) {
        #expect(throws: UsageError.badValue(option: "--length")) { try parse("new", "n", "--length", length) }
    }

    @Test func theLengthBoundsAreInclusive() throws {
        for length in [16, 128] {
            let command = try parse("new", "n", "--length", String(length))
            guard case .new(let options) = command else { Issue.record("not new"); return }
            #expect(options.length == length)
        }
    }

    @Test func aCharsetOtherThanAlnumOrFullIsRefused() {
        #expect(throws: UsageError.badValue(option: "--charset")) { try parse("new", "n", "--charset", "symbols") }
        #expect(throws: UsageError.badValue(option: "--charset")) { try parse("new", "n", "--charset", "FULL") }
    }

    @Test func newNeedsAValidNameOfAtMost100Characters() throws {
        #expect(throws: UsageError.missingName) { try parse("new") }
        #expect(throws: UsageError.missingName) { try parse("new", "--length", "20") }
        #expect(throws: UsageError.badName) { try parse("new", "") }
        #expect(throws: UsageError.badName) { try parse("new", String(repeating: "a", count: 101)) }
        #expect(throws: UsageError.badName) { try parse("new", "tab\there") }
        let longest = String(repeating: "a", count: 100)
        #expect(try parse("new", longest) == .new(NewOptions(name: longest, username: nil, uri: nil, env: nil, length: 32, charset: .alnum)))
    }

    @Test func newRefusesRepeatedOptionsAndAnInvalidEnvName() {
        #expect(throws: UsageError.duplicateOption("--length")) { try parse("new", "n", "--length", "20", "--length", "30") }
        #expect(throws: UsageError.duplicateOption("--username")) { try parse("new", "n", "--username", "a", "--username", "b") }
        #expect(throws: UsageError.badValue(option: "--env")) { try parse("new", "n", "--env", "bad name") }
        #expect(throws: UsageError.badValue(option: "--env")) { try parse("new", "n", "--env", "LD_PRELOAD") }
        #expect(throws: UsageError.unexpectedArgument("second")) { try parse("new", "n", "second") }
    }

    @Test func newValuesWithControlCharactersAreRefused() {
        #expect(throws: UsageError.badValue(option: "--username")) { try parse("new", "n", "--username", "a\nb") }
        #expect(throws: UsageError.badValue(option: "--uri")) { try parse("new", "n", "--uri", "https://x\u{1B}") }
        #expect(throws: UsageError.badValue(option: "--username")) { try parse("new", "n", "--username", "") }
    }

    // MARK: messages

    @Test func everyErrorHasAFixedNonEmptyMessage() {
        let errors: [UsageError] = [.unknownCommand("x"), .unknownOption("x"), .missingItem, .missingName, .missingCommand,
                                    .missingValue(option: "--env"), .badBinding(option: "--env"), .badValue(option: "--length"),
                                    .duplicateName("A"), .duplicateOption("--bw"), .unexpectedArgument("x"), .badName]
        for error in errors { #expect(!error.message.isEmpty && !error.message.contains("\n")) }
    }
}

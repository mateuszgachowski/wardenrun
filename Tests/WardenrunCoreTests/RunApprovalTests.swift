import Foundation
import Testing
@testable import WardenrunCore

private func request(item: String = "api", path: String = "/usr/bin/true", args: [String] = [], argv0: String? = nil,
                     parent: String? = "claude", env: [String: String] = [:], writable: Bool = false,
                     previousHash: String? = nil, hash: String = "aa", injections: [String] = []) -> ApprovalRequest {
    ApprovalRequest(item: item,
                    executable: ResolvedExecutable(path: path, argv: [argv0 ?? (path as NSString).lastPathComponent] + args, sha256: hash),
                    parent: parent, callerEnvironment: env, executableIsWritable: writable, previousHash: previousHash,
                    injections: injections)
}

private func text(_ request: ApprovalRequest) throws -> String { try ApprovalTextBuilder.text(for: request) }

struct RunApprovalTests {
    @Test func formatIsTagsThenUseSecretItemToRunExeArgsFromParentEnd() throws {
        let result = try text(request(path: "/usr/bin/true", args: ["-s", "https://x.example/a,b=1"]))
        #expect(result == "use secret \"api\" to run: /usr/bin/true -s https://x.example/a,b=1 (from claude) [end]")
    }

    @Test func noParentOmitsTheFromClause() throws {
        #expect(try text(request(parent: nil)) == "use secret \"api\" to run: /usr/bin/true [end]")
    }

    @Test func argumentsWithSpacesOrQuotesAreShellQuoted() throws {
        let result = try text(request(args: ["two words", "it's", "", "a$b", "x;y"]))
        #expect(result.contains(" 'two words' 'it'\\''s' '' 'a$b' 'x;y' "))
    }

    @Test func aPathWithSpacesIsQuotedToo() throws {
        #expect(try text(request(path: "/Applications/My Tool/bin/tool")).contains("run: '/Applications/My Tool/bin/tool' "))
    }

    @Test func controlCharactersNewlinesAndBidiOverridesAreVisibleEscapes() throws {
        let nasty = "a\nb\r\tc\u{7}d\u{202E}e\u{2066}f\u{200B}g\u{85}h"
        let result = try text(request(args: [nasty]))
        #expect(result.contains("a\\nb\\r\\tc\\u{7}d\\u{202E}e\\u{2066}f\\u{200B}g\\u{85}h"))
        for scalar in result.unicodeScalars {
            #expect(scalar.value >= 0x20 && scalar.value != 0x7F, "raw control scalar \(scalar.value)")
            #expect(!(0x80...0x9F).contains(scalar.value))
            #expect(scalar.properties.generalCategory != .format)
        }
    }

    @Test func aLiteralBackslashIsDoubledSoEscapesStayUnambiguous() throws {
        let result = try text(request(args: ["a\\nb"]))
        #expect(result.contains("'a\\\\nb'"))
    }

    @Test func theItemNameCannotCloseItsQuotesOrForgeTheSentence() throws {
        let result = try text(request(item: "api\" to run: /bin/true (from x) [end] \""))
        #expect(result.hasPrefix("use secret \"api\\\" to run: /bin/true (from x) [end] \\\"\" to run: /usr/bin/true"))
        #expect(result.hasSuffix("[end]"))
    }

    @Test func nulInTheItemNameIsEscaped() throws {
        let result = try text(request(item: "a\u{0}b"))
        #expect(result.contains("\"a\\u{0}b\""))
    }

    @Test func aNonAsciiPathOrArgv0OrItemAddsTheTag() throws {
        #expect(try text(request(path: "/opt/tооl/run")).hasPrefix("[non-ASCII] "))          // Cyrillic o
        #expect(try text(request(argv0: "tооl")).hasPrefix("[non-ASCII] "))
        #expect(try text(request(item: "ключ")).hasPrefix("[non-ASCII] "))
        #expect(try text(request(args: ["żółć"])).hasPrefix("[non-ASCII] "), "an argument counts too: a look-alike letter in a host name")
    }

    @Test(arguments: [("sh", ["-c", "echo hi"]), ("bash", ["-lc", "echo hi"]), ("zsh", ["-c", "x"]),
                      ("python3", ["-c", "print(1)"]), ("python3.12", ["-c", "x"])])
    func shellDashCAndPythonDashCAreTagged(name: String, args: [String]) throws {
        #expect(try text(request(path: "/usr/bin/" + name, args: args)).hasPrefix("[shell -c] "))
    }

    @Test func aShellRunningAScriptIsNotTagged() throws {
        #expect(!(try text(request(path: "/bin/sh", args: ["script.sh"]))).contains("[shell -c]"))
        #expect(!(try text(request(path: "/bin/sh", args: ["--command"]))).contains("[shell -c]"))
    }

    @Test(arguments: ["curl", "wget", "nc", "ssh", "scp"])
    func networkToolsAreTagged(name: String) throws {
        #expect(try text(request(path: "/usr/bin/" + name)).hasPrefix("[network] "))
    }

    @Test(arguments: ["env", "printenv"])
    func envDumpIsTagged(name: String) throws {
        #expect(try text(request(path: "/usr/bin/" + name)).hasPrefix("[env dump] "))
    }

    @Test func aWritableExecutableIsTagged() throws {
        #expect(try text(request(writable: true)).hasPrefix("[writable exe] "))
        #expect(!(try text(request(writable: false))).contains("[writable exe]"))
    }

    @Test func aChangedHashIsTaggedOnlyWhenThereIsAPreviousHashThatDiffers() throws {
        #expect(try text(request(previousHash: "bb", hash: "aa")).hasPrefix("[exe changed] "))
        #expect(!(try text(request(previousHash: "aa", hash: "aa"))).contains("[exe changed]"))
        #expect(!(try text(request(previousHash: nil, hash: "aa"))).contains("[exe changed]"))
    }

    @Test func riskyCallerVariablesAreTaggedByNameNeverByValue() throws {
        let result = try text(request(env: ["NODE_OPTIONS": "--require /tmp/evil-VALUE.js", "PATH": "/usr/bin", "LD_PRELOAD": "/x"]))
        #expect(result.hasPrefix("[env: LD_PRELOAD] [env: NODE_OPTIONS] "))
        #expect(!result.contains("evil-VALUE"))
    }

    @Test func tagsComeInTheDocumentedOrder() throws {
        let result = try text(request(path: "/opt/tооl/run", env: ["BASH_ENV": "x"], writable: true, previousHash: "bb"))
        #expect(result.hasPrefix("[writable exe] [exe changed] [non-ASCII] [env: BASH_ENV] use secret"))
    }

    @Test func exactly400CharactersPass401IsRefusedWithTheFixedSentence() throws {
        let one = try text(request(args: ["a"])).utf16.count
        let exactly400 = 400 - one + 1            // an unquoted argument of n letters adds n - 1 over the one-letter text
        let exact = try text(request(args: [String(repeating: "a", count: exactly400)]))
        #expect(exact.utf16.count == 400)
        let shorter = try text(request(args: [String(repeating: "a", count: exactly400 - 1)]))
        #expect(shorter.utf16.count == 399)
        do {
            _ = try text(request(args: [String(repeating: "a", count: exactly400 + 1)]))
            Issue.record("401 characters must be refused")
        } catch let error as ApprovalTextError {
            #expect(error == .tooLong(401))
            #expect(error.message == "command too long to review (401 > 400); put it in a script file")
        }
    }

    @Test func theTextIsNeverShortenedAndAlwaysEndsWithEnd() throws {
        for count in [0, 1, 50, 150] {
            let result = try text(request(args: Array(repeating: "x", count: count)))
            #expect(result.hasSuffix(" [end]"))
            #expect(result.components(separatedBy: " x").count - 1 == count)
        }
    }

    @Test func charactersAreCountedAfterEscapingNotBefore() throws {
        // 120 newlines are 120 raw characters but 240 after escaping.
        let result = try text(request(args: [String(repeating: "\n", count: 120)]))
        #expect(result.utf16.count > 240)
        #expect(throws: ApprovalTextError.self) { _ = try text(request(args: [String(repeating: "\n", count: 200)])) }
    }

    @Test func theSheetSaysWhereTheSecretGoes() throws {
        let result = try text(request(injections: ["$GIT_DIR", "file $CERT", "stdin"]))
        #expect(result == "use secret \"api\" as $GIT_DIR, file $CERT, stdin to run: /usr/bin/true (from claude) [end]")
    }

    @Test func withoutFlagsTheSheetHasNoAsClause() throws {
        #expect(try !text(request()).contains(" as "))
    }

    @Test func theInjectionNamesCountAgainstTheBudget() {
        let many = (0..<30).map { "$VARIABLE_NUMBER_\($0)" }
        do {
            _ = try text(request(injections: many))
            Issue.record("expected a refusal")
        } catch let error as ApprovalTextError {
            guard case .tooLong = error else { Issue.record("wrong error"); return }
        } catch {
            Issue.record("wrong error type")
        }
    }

    @Test func nonASCIIInAnArgumentIsTagged() throws {
        let result = try text(request(path: "/usr/bin/curl", args: ["https://\u{430}pi.example.com"]))
        #expect(result.hasPrefix("[network] [non-ASCII] ") || result.contains("[non-ASCII]"))
    }

    @Test func plainASCIIArgumentsAreNotTaggedAsNonASCII() throws {
        #expect(try !text(request(args: ["--flag", "value"])).contains("[non-ASCII]"))
    }

    @Test(arguments: ["\u{A0}", "\u{2800}", "\u{3164}", "\u{3000}", "\u{115F}", "\u{FFA0}", "\u{2003}"])
    func blankLookingCharactersAreVisibleEscapes(scalar: String) throws {
        let result = try text(request(args: ["a" + scalar + "b"]))
        let value = scalar.unicodeScalars.first!.value
        #expect(result.contains("a\\u{" + String(value, radix: 16, uppercase: true) + "}b"))
        #expect(!result.contains(scalar))
    }

    @Test func aNormalSpaceAndLettersWithDiacriticsAreLeftAlone() throws {
        let result = try text(request(args: ["zażółć gęślą"]))
        #expect(result.contains("'zażółć gęślą'"))
    }
}

public enum EnvPolicyError: Error, Equatable {
    case invalidName(String)
    case forbiddenName(String)
    case invalidValue(name: String)
}

/// Which environment variables reach `bw` and the approved child.
public enum EnvPolicy {
    /// The whole environment of a `bw` process. It takes no parameter that carries the
    /// caller's environment, so inheriting anything by accident is impossible: no
    /// `NODE_OPTIONS`, no `BW_SESSION`, no `DYLD_*`.
    public static func bwEnvironment(home: String,
                                     appDataDir: String,
                                     pinnedDirectories: [String],
                                     lang: String = "en_US.UTF-8",
                                     nodeExtraCACerts: String? = nil,
                                     httpsProxy: String? = nil) -> [String: String] {
        var env = [
            "HOME": home,
            "LANG": lang,
            "BITWARDENCLI_APPDATA_DIR": appDataDir,
            "BW_NOINTERACTION": "true",
            "PATH": pinnedDirectories.joined(separator: ":"),
        ]
        if let nodeExtraCACerts { env["NODE_EXTRA_CA_CERTS"] = nodeExtraCACerts }
        if let httpsProxy { env["https_proxy"] = httpsProxy }
        return env
    }

    /// The caller's own environment plus the variables to inject; an injected one wins.
    public static func childEnvironment(caller: [String: String],
                                        injected: [String: String]) throws -> [String: String] {
        for (name, value) in injected {
            try validateInjectedName(name)
            if value.utf8.contains(0) { throw EnvPolicyError.invalidValue(name: name) }
        }
        return caller.merging(injected) { _, new in new }
    }

    /// A name must be ASCII letters, digits and `_`, not start with a digit. Names starting
    /// with `DYLD_` or `LD_` are refused: they make the loader pull code into the approved
    /// child, and an item in the vault is data somebody else may have been able to edit.
    public static func validateInjectedName(_ name: String) throws {
        let bytes = Array(name.utf8)
        guard let first = bytes.first, !isDigit(first), bytes.allSatisfy(isNameByte) else {
            throw EnvPolicyError.invalidName(name)
        }
        if name.hasPrefix("DYLD_") || name.hasPrefix("LD_") { throw EnvPolicyError.forbiddenName(name) }
    }

    /// Names in `environment` that the dynamic loader treats as injection points on macOS.
    public static func loaderVariables(in environment: [String: String]) -> [String] {
        environment.keys.filter { $0.hasPrefix("DYLD_") }.sorted()
    }

    private static let riskyNames: Set<String> = [
        "BASH_ENV", "ENV", "SHELLOPTS", "PS4", "PROMPT_COMMAND", "IFS",
        "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
        "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
        "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EXEC_PATH",
    ]
    private static let riskyPrefixes = ["LD_", "DYLD_", "BASH_FUNC_"]

    /// Names in `environment` that make an ordinary program load or run somebody's code at
    /// startup (`NODE_OPTIONS=--require`, `BASH_ENV`, `LD_PRELOAD`, ...). The approval sheet shows
    /// the command but not the environment, so these should appear on it as `[env: NAME]`. The
    /// list is the common offenders, not a complete one; it is there to inform the human, not to
    /// block (people use `NODE_OPTIONS` for legitimate reasons).
    public static func riskyVariables(in environment: [String: String]) -> [String] {
        environment.keys.filter { name in
            riskyNames.contains(name) || riskyPrefixes.contains { name.hasPrefix($0) }
        }.sorted()
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")
    }

    private static func isNameByte(_ byte: UInt8) -> Bool {
        isDigit(byte) || byte == UInt8(ascii: "_")
            || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
    }
}

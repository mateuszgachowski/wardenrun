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

    /// A name must be ASCII letters, digits and `_`, not start with a digit. A name that changes how
    /// programs behave is refused as a target for a secret: the loader variables (`DYLD_`, `LD_`),
    /// every risky name (`BASH_ENV`, `NODE_OPTIONS`, proxies, ...), and the ones that choose a
    /// directory or a program (`HOME`, `PATH`, `TMPDIR`, `XDG_*`, `GIT_*`, `npm_config_*`). Whoever
    /// picks the name picks where the secret ends up: `GIT_DIR=password git init` would create a
    /// directory named after it, and an item in the vault is data somebody else may have edited.
    public static func validateInjectedName(_ name: String) throws {
        let bytes = Array(name.utf8)
        guard let first = bytes.first, !isDigit(first), bytes.allSatisfy(isNameByte) else {
            throw EnvPolicyError.invalidName(name)
        }
        if riskyNames.contains(name) || targetOnlyNames.contains(name)
            || (riskyPrefixes + targetOnlyPrefixes).contains(where: { name.hasPrefix($0) }) {
            throw EnvPolicyError.forbiddenName(name)
        }
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
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EXEC_PATH", "GIT_PROXY_COMMAND",
        // `/usr/bin/git`, `python3`, `make` and `swift` are shims that run whatever this points to.
        "DEVELOPER_DIR", "TOOLCHAINS",
        // A proxy or a different certificate store sits between the program and the server.
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
        // npm reads its settings from the environment too; only the ones that run or redirect.
        "NPM_CONFIG_SCRIPT_SHELL", "NPM_CONFIG_PREFIX", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG",
        "npm_config_script_shell", "npm_config_prefix", "npm_config_userconfig", "npm_config_globalconfig",
    ]
    private static let riskyPrefixes = ["LD_", "DYLD_", "BASH_FUNC_", "GIT_CONFIG"]

    /// Ordinary variables that nobody should be able to point a secret at: they choose where a
    /// program works or which program it runs. They are not tagged on the sheet when the caller
    /// sets them (everybody has them), but they are not valid targets.
    private static let targetOnlyNames: Set<String> = [
        "HOME", "PATH", "TMPDIR", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "CDPATH", "MANPATH",
    ]
    private static let targetOnlyPrefixes = ["XDG_", "GIT_", "NPM_CONFIG_", "npm_config_"]

    /// Names in `environment` that make an ordinary program load or run somebody's code at
    /// startup, or send its traffic somewhere else (`NODE_OPTIONS=--require`, `BASH_ENV`,
    /// `LD_PRELOAD`, `DEVELOPER_DIR`, `HTTPS_PROXY`, ...). The approval sheet shows the command but
    /// not the environment, so these should appear on it as `[env: NAME]`. The list is the common
    /// offenders, not a complete one (a `PATH`, a dotfile or a tool's own config file can redirect
    /// an honest program too); it is there to inform the human, not to block (people use
    /// `NODE_OPTIONS` and proxies for legitimate reasons).
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

import Testing
@testable import WardenrunCore

struct EnvPolicyTests {
    private let base: [String: String] = [
        "HOME": "/h", "LANG": "en_US.UTF-8", "BITWARDENCLI_APPDATA_DIR": "/h/.config/wardenrun/bw",
        "BW_NOINTERACTION": "true", "PATH": "/a:/b",
    ]

    @Test func bwEnvironmentIsExactlyTheAllowlist() {
        let env = EnvPolicy.bwEnvironment(home: "/h", appDataDir: "/h/.config/wardenrun/bw",
                                          pinnedDirectories: ["/a", "/b"])
        #expect(env == base)
    }

    @Test func bwEnvironmentAddsTheCAAndProxyOnlyWhenGiven() {
        let env = EnvPolicy.bwEnvironment(home: "/h", appDataDir: "/h/.config/wardenrun/bw",
                                          pinnedDirectories: ["/a", "/b"],
                                          nodeExtraCACerts: "/ca.pem", httpsProxy: "https://p:3128")
        var expected = base
        expected["NODE_EXTRA_CA_CERTS"] = "/ca.pem"
        expected["https_proxy"] = "https://p:3128"
        #expect(env == expected)
    }

    @Test func bwEnvironmentNeverHasAnythingOutsideTheAllowlist() {
        let allowed: Set<String> = ["HOME", "LANG", "BITWARDENCLI_APPDATA_DIR", "BW_NOINTERACTION",
                                    "PATH", "NODE_EXTRA_CA_CERTS", "https_proxy"]
        for ca in [nil, "/ca.pem"] {
            for proxy in [nil, "https://p:3128"] {
                let env = EnvPolicy.bwEnvironment(home: "/h", appDataDir: "/d", pinnedDirectories: ["/a"],
                                                  nodeExtraCACerts: ca, httpsProxy: proxy)
                #expect(Set(env.keys).isSubset(of: allowed))
                #expect(env["BW_SESSION"] == nil)
                #expect(env["NODE_OPTIONS"] == nil)
            }
        }
    }

    @Test func bwEnvironmentUsesTheGivenLanguage() {
        let env = EnvPolicy.bwEnvironment(home: "/h", appDataDir: "/d", pinnedDirectories: ["/a"], lang: "C")
        #expect(env["LANG"] == "C")
    }

    @Test func childEnvironmentIsTheCallersPlusTheInjectedOnesAndInjectedWins() throws {
        let env = try EnvPolicy.childEnvironment(caller: ["A": "1", "PATH": "/x"], injected: ["B": "2", "A": "9"])
        #expect(env == ["A": "9", "B": "2", "PATH": "/x"])
    }

    @Test func childEnvironmentRejectsAnInvalidInjectedName() {
        #expect(throws: EnvPolicyError.invalidName("1ABC")) {
            try EnvPolicy.childEnvironment(caller: [:], injected: ["1ABC": "x"])
        }
    }

    @Test func childEnvironmentRejectsAForbiddenInjectedName() {
        #expect(throws: EnvPolicyError.forbiddenName("DYLD_INSERT_LIBRARIES")) {
            try EnvPolicy.childEnvironment(caller: [:], injected: ["DYLD_INSERT_LIBRARIES": "/evil.dylib"])
        }
    }

    @Test func childEnvironmentRejectsANulInAnInjectedValue() {
        #expect(throws: EnvPolicyError.invalidValue(name: "TOKEN")) {
            try EnvPolicy.childEnvironment(caller: [:], injected: ["TOKEN": "ab\u{0}cd"])
        }
    }

    @Test(arguments: ["API_KEY", "_x1", "a", "Path2"])
    func validNamesAreAccepted(name: String) throws {
        try EnvPolicy.validateInjectedName(name)
    }

    @Test(arguments: ["", "1ABC", "A-B", "A=B", "A B", "A\u{0}B", "ÄB", "A.B"])
    func invalidNamesAreRejected(name: String) {
        #expect(throws: EnvPolicyError.invalidName(name)) { try EnvPolicy.validateInjectedName(name) }
    }

    @Test(arguments: ["DYLD_INSERT_LIBRARIES", "DYLD_X", "LD_PRELOAD", "LD_LIBRARY_PATH"])
    func loaderNamesAreForbidden(name: String) {
        #expect(throws: EnvPolicyError.forbiddenName(name)) { try EnvPolicy.validateInjectedName(name) }
    }

    @Test func namesThatOnlyLookLikeLoaderNamesAreFine() throws {
        try EnvPolicy.validateInjectedName("OLD_PASSWORD")
        try EnvPolicy.validateInjectedName("DYLDX")
        try EnvPolicy.validateInjectedName("dyld_lowercase")   // dyld only honours the upper-case prefix
    }

    @Test func loaderVariablesAreListedSorted() {
        #expect(EnvPolicy.loaderVariables(in: ["DYLD_X": "1", "PATH": "/x", "DYLD_A": "2"]) == ["DYLD_A", "DYLD_X"])
        #expect(EnvPolicy.loaderVariables(in: ["PATH": "/x"]).isEmpty)
    }

    @Test func riskyVariablesNameTheInterpreterAndShellStartupHooks() {
        let env = ["NODE_OPTIONS": "--require /tmp/x.js", "BASH_ENV": "/tmp/x", "PYTHONPATH": "/tmp", "PERL5OPT": "-Mx",
                   "RUBYOPT": "-rx", "GIT_SSH_COMMAND": "ssh -o x", "JAVA_TOOL_OPTIONS": "-javaagent:x.jar",
                   "LD_PRELOAD": "/x.so", "DYLD_INSERT_LIBRARIES": "/x.dylib", "BASH_FUNC_ls%%": "() { x; }",
                   "PATH": "/usr/bin", "HOME": "/h", "API_KEY": "k", "OLD_PASSWORD": "p"]
        #expect(EnvPolicy.riskyVariables(in: env) == [
            "BASH_ENV", "BASH_FUNC_ls%%", "DYLD_INSERT_LIBRARIES", "GIT_SSH_COMMAND", "JAVA_TOOL_OPTIONS",
            "LD_PRELOAD", "NODE_OPTIONS", "PERL5OPT", "PYTHONPATH", "RUBYOPT",
        ])
    }

    @Test func riskyVariablesIsEmptyForAnOrdinaryEnvironment() {
        #expect(EnvPolicy.riskyVariables(in: ["PATH": "/usr/bin", "HOME": "/h", "LANG": "C", "TERM": "xterm"]).isEmpty)
    }

    @Test func variablesThatRedirectWhatAnOrdinaryProgramRunsAreRisky() {
        let names = ["DEVELOPER_DIR", "TOOLCHAINS", "GIT_SSH", "GIT_PROXY_COMMAND", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0",
                     "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY",
                     "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
                     "NPM_CONFIG_SCRIPT_SHELL", "npm_config_prefix", "NPM_CONFIG_USERCONFIG"]
        for name in names {
            #expect(EnvPolicy.riskyVariables(in: [name: "x"]) == [name], "\(name)")
        }
    }

    @Test func ordinaryAndNpmScriptVariablesAreNotRisky() {
        let environment = ["PATH": "/usr/bin", "HOME": "/Users/x", "LANG": "en_US.UTF-8", "TERM": "xterm", "USER": "x",
                           "SHELL": "/bin/zsh", "TMPDIR": "/tmp", "EDITOR": "vi", "PAGER": "less",
                           "npm_config_user_agent": "npm/10", "npm_config_cache": "/c", "npm_lifecycle_event": "test"]
        #expect(EnvPolicy.riskyVariables(in: environment).isEmpty)
    }

    @Test(arguments: ["HOME", "PATH", "TMPDIR", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "CDPATH", "XDG_CACHE_HOME",
                      "XDG_CONFIG_HOME", "GIT_DIR", "GIT_SSH", "GIT_WORK_TREE", "DEVELOPER_DIR", "BASH_ENV", "NODE_OPTIONS",
                      "PYTHONPATH", "HTTPS_PROXY", "NPM_CONFIG_PREFIX", "npm_config_cache"])
    func namesThatChangeHowProgramsBehaveAreRefusedAsInjectionTargets(name: String) {
        #expect(throws: EnvPolicyError.forbiddenName(name)) { try EnvPolicy.validateInjectedName(name) }
    }

    @Test(arguments: ["NPM_TOKEN", "GITHUB_TOKEN", "API_KEY", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "MY_HOME", "HOMEBREW_TOKEN", "TOKEN"])
    func ordinaryCredentialNamesStayAllowedAsInjectionTargets(name: String) throws {
        try EnvPolicy.validateInjectedName(name)
    }
}

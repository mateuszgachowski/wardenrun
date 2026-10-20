import Foundation

/// What the person typed at `wardenrun setup`, before any of it is checked.
public struct SetupInput: Sendable {
    public var serverURL: String
    public var email: String
    public var organizationID: String
    public var collectionIDs: [String]
    public var masterPassword: SecretBuffer
    public var bwPin: BwPin
    public var nodeExtraCACerts: String?
    public var httpsProxy: String?

    public init(serverURL: String, email: String, organizationID: String, collectionIDs: [String],
                masterPassword: SecretBuffer, bwPin: BwPin, nodeExtraCACerts: String?, httpsProxy: String?) {
        self.serverURL = serverURL
        self.email = email
        self.organizationID = organizationID
        self.collectionIDs = collectionIDs
        self.masterPassword = masterPassword
        self.bwPin = bwPin
        self.nodeExtraCACerts = nodeExtraCACerts
        self.httpsProxy = httpsProxy
    }
}

/// Texts are fixed; a case names a field or a step, never a value.
public enum SetupError: Error, Equatable, Sendable {
    case notInteractive
    case cancelled
    case denied
    case invalid(field: String)
    case approvalTextTooLong
    case bwFailed(step: String)
    case verifyFailed(summary: String)
    case installFailed(reason: String)

    public var message: String {
        switch self {
        case .notInteractive: return "setup needs a terminal: the master password is typed here, never passed as an argument"
        case .cancelled: return "setup was cancelled"
        case .denied: return "setup was not approved"
        case .invalid(let field): return "the \(field) is missing or not acceptable"
        case .approvalTextTooLong: return "the settings are too long to show in one approval; nothing was changed"
        case .bwFailed(let step): return "bw failed at the step \"\(step)\"; nothing was saved"
        case .verifyFailed(let summary): return "the login did not check out (\(summary)); nothing was saved"
        case .installFailed(let reason): return "bw could not be installed: \(reason)"
        }
    }
}

/// `wardenrun setup` (DESIGN 5.8): everything except the typing and the Touch ID sheet. Nothing
/// here saves the protected item; the caller does that only after `verify` passes.
public enum Setup {
    /// The approval text may not be longer than this; a longer one is refused, never cut.
    public static let approvalBudget = 400

    public static func requireInteractive(_ isInteractive: Bool) throws {
        if !isInteractive { throw SetupError.notInteractive }
    }

    /// All validation of the typed values, with the field named when one fails.
    public static func makeConfig(_ input: SetupInput) throws -> ProtectedConfig {
        let email = input.email
        guard !email.isEmpty, email.contains("@"), !email.unicodeScalars.contains(where: { $0.properties.isWhitespace || $0.value < 0x20 }) else {
            throw SetupError.invalid(field: "email")
        }
        // `bw --passwordfile` reads one line, so a newline in the password would silently shorten it.
        guard input.masterPassword.withUnsafeBytes({ !$0.contains(0x0A) && !$0.contains(0x0D) && !$0.contains(0x00) }) else {
            throw SetupError.invalid(field: "password")
        }
        guard let url = URL(string: input.serverURL) else { throw SetupError.invalid(field: "server") }
        do {
            return try ProtectedConfig(serverURL: url, accountEmail: email, organizationID: input.organizationID,
                                       collectionIDs: input.collectionIDs, masterPassword: input.masterPassword,
                                       bwPin: input.bwPin, nodeExtraCACerts: input.nodeExtraCACerts, httpsProxy: input.httpsProxy)
        } catch let error as ConfigError {
            switch error {
            case .insecureServerURL, .invalidServerURL: throw SetupError.invalid(field: "server")
            case .missingField(let name), .invalidValue(let name):
                switch name {
                case "server_url": throw SetupError.invalid(field: "server")
                case "account_email": throw SetupError.invalid(field: "email")
                case "organization_id": throw SetupError.invalid(field: "organization")
                case "collection_ids": throw SetupError.invalid(field: "collections")
                case "master_password": throw SetupError.invalid(field: "password")
                case "team_id", "path": throw SetupError.invalid(field: "bw")
                default: throw SetupError.invalid(field: "settings")
                }
            case .emptyCollections: throw SetupError.invalid(field: "collections")
            default: throw SetupError.invalid(field: "settings")
            }
        }
    }

    // MARK: approval text

    /// What the Touch ID sheet says: the new values next to the old ones, never the password.
    public static func approvalText(old: ProtectedConfig?, new: ProtectedConfig) throws -> String {
        func line(_ label: String, _ newValue: String, _ oldValue: String?) -> String {
            guard let oldValue else { return "\(label): \(newValue)" }
            return oldValue == newValue ? "\(label): \(newValue) (unchanged)" : "\(label): \(newValue) (was: \(oldValue))"
        }
        func pinText(_ config: ProtectedConfig) -> String {
            switch config.bwPin {
            case .signedRelease(let team, let path): return "team \(team) \(path)"
            }
        }
        var lines = [old == nil ? "First setup: there is no previous value."
                                : "Change the stored vault settings. Old values in brackets."]
        lines.append(line("server", new.serverURL.absoluteString, old?.serverURL.absoluteString))
        lines.append(line("account", new.accountEmail, old?.accountEmail))
        lines.append(line("organization", new.organizationID, old?.organizationID))
        lines.append(line("collections", new.collectionIDs.joined(separator: ", "), old?.collectionIDs.joined(separator: ", ")))
        lines.append(line("bw", pinText(new), old.map(pinText)))
        if old == nil { lines[0] = "First setup: there is no previous value." }
        let text = lines.joined(separator: "\n")
        guard text.count <= approvalBudget else { throw SetupError.approvalTextTooLong }
        return text
    }

    // MARK: bw

    /// Logs the pinned `bw` into the account, under `bw.lock`: `logout` (it may have nothing to log
    /// out of), `config server`, then `login` with the master password on an inherited pipe, so
    /// that it is in no argument, no environment variable and no file.
    public static func configureBw(config: ProtectedConfig, appDataDir: String, home: String, lockPath: String,
                                   signature: BwSignatureChecker, timeouts: BwTimeouts) throws {
        let lock: BwLock
        do { lock = try BwLock.acquire(path: lockPath, timeout: timeouts.lockWait) } catch { throw SetupError.bwFailed(step: "lock") }
        defer { lock.release() }

        let spec: BwLaunchSpec
        do { spec = try BwBinaryPolicy.launchSpec(for: config.bwPin, signature: signature) } catch { throw SetupError.bwFailed(step: "pin") }
        let environment = EnvPolicy.bwEnvironment(home: home, appDataDir: appDataDir, pinnedDirectories: spec.pinnedDirectories,
                                                  nodeExtraCACerts: config.nodeExtraCACerts, httpsProxy: config.httpsProxy)

        _ = try? runStep(spec: spec, arguments: ["logout", "--quiet", "--nointeraction"], environment: environment,
                         deadline: 30, step: "logout")
        try runStep(spec: spec, arguments: ["config", "server", config.serverURL.absoluteString, "--nointeraction"],
                    environment: environment, deadline: 30, step: "config server")

        var ends: [Int32] = [-1, -1]
        guard pipe(&ends) == 0 else { throw SetupError.bwFailed(step: "login") }
        for descriptor in ends { _ = fcntl(descriptor, F_SETFD, FD_CLOEXEC) }
        defer { close(ends[0]); close(ends[1]) }
        // The password and a newline are small enough for the pipe buffer, so they can be written
        // before the child exists; closing the write end then gives `bw` its end-of-file.
        let written = config.masterPassword.withUnsafeBytes { bytes -> Bool in
            var offset = 0
            while offset < bytes.count {
                let count = write(ends[1], bytes.baseAddress! + offset, bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { return false }
                offset += count
            }
            return true
        }
        guard written, write(ends[1], "\n", 1) == 1 else { throw SetupError.bwFailed(step: "login") }
        close(ends[1])
        ends[1] = -1
        try runStep(spec: spec, arguments: ["login", config.accountEmail, "--passwordfile", "/dev/fd/3", "--quiet", "--nointeraction"],
                    environment: environment, inherit: [(parent: ends[0], child: 3)], deadline: 120, step: "login")
    }

    private static func runStep(spec: BwLaunchSpec, arguments: [String], environment: [String: String],
                                inherit: [(parent: Int32, child: Int32)] = [], deadline: TimeInterval, step: String) throws {
        let child: BwChild
        do {
            child = try BwProcess.start(spec: spec, arguments: arguments, environment: environment, inherit: inherit,
                                        captureLimit: 1 << 16)
        } catch { throw SetupError.bwFailed(step: step) }
        // Whatever `bw` printed is dropped: it is never shown and never logged.
        defer { child.terminate(grace: 1) }
        guard child.wait(timeout: deadline) == .exited(0) else { throw SetupError.bwFailed(step: step) }
    }

    /// Unlock and lock, nothing else: proves that the password and the profile belong together.
    public static func verify(vault: BwVault) throws {
        do {
            try vault.verifyLogin()
        } catch let error as BwError {
            throw SetupError.verifyFailed(summary: error.summary)
        }
    }

    // MARK: install

    /// Copies the signed release `bw` to `destination` (a directory only the user can enter),
    /// checks the copy before it takes its name and the file at its name afterwards, and returns
    /// the pin for it. A copy that fails the check leaves the old file untouched.
    public static func installBw(from source: String, teamID: String, to destination: String,
                                 signature: BwSignatureChecker) throws -> BwPin {
        var info = stat()
        guard stat(source, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            throw SetupError.installFailed(reason: "the bw file to copy is missing")
        }
        let directory = (destination as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            chmod(directory, 0o700)
        } catch { throw SetupError.installFailed(reason: "the install directory cannot be created") }

        let temporary = directory + "/.bw.new-" + UUID().uuidString
        defer { unlink(temporary) }
        do { try FileManager.default.copyItem(atPath: source, toPath: temporary) } catch {
            throw SetupError.installFailed(reason: "the bw file could not be copied")
        }
        guard chmod(temporary, 0o700) == 0 else { throw SetupError.installFailed(reason: "the copy could not be made executable") }
        do { try signature.check(path: temporary, teamID: teamID) } catch {
            throw SetupError.installFailed(reason: "the copy does not carry the expected signature")
        }
        guard rename(temporary, destination) == 0 else { throw SetupError.installFailed(reason: "the copy could not be put in place") }
        do { try signature.check(path: destination, teamID: teamID) } catch {
            unlink(destination)
            throw SetupError.installFailed(reason: "the installed file does not carry the expected signature")
        }
        return .signedRelease(teamID: teamID, path: destination)
    }
}

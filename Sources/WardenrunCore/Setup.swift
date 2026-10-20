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
    /// There was no way to ask a human (no Touch ID, no screen session). `reason` is one of the
    /// approver's fixed sentences.
    case approvalUnavailable(reason: String)

    public var message: String {
        switch self {
        case .notInteractive: return "setup needs a terminal: the master password is typed here, never passed as an argument"
        case .cancelled: return "setup was cancelled"
        case .denied: return "setup was not approved"
        case .invalid(let field): return "the \(field) is missing or not acceptable"
        case .approvalTextTooLong: return "the settings are too long to show in one approval; nothing was changed"
        case .bwFailed(let step):
            let hint = step == "login" ? " (check the password; an account with two-step login is not supported yet)" : ""
            return "bw failed at the step \"\(step)\"\(hint); nothing was saved"
        case .verifyFailed(let summary): return "the login did not check out (\(summary)); nothing was saved"
        case .installFailed(let reason): return "bw could not be installed: \(reason)"
        case .approvalUnavailable(let reason): return "no approval was possible (\(reason)); nothing was changed"
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
        // Printable ASCII only: the e-mail is shown in the approval text, and look-alike, invisible
        // and bidirectional characters have no place in an account name.
        guard !email.isEmpty, email.contains("@"), email.unicodeScalars.allSatisfy({ (0x21...0x7E).contains($0.value) }) else {
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
    /// Every value is escaped; `replacesUnreadable` says that an item exists that this build cannot
    /// read and is about to be replaced.
    public static func approvalText(old: ProtectedConfig?, new: ProtectedConfig, replacesUnreadable: Bool = false) throws -> String {
        func shown(_ value: String) -> String { TextEscaping.escape(value) }
        func line(_ label: String, _ newValue: String, _ oldValue: String?, elideSame: Bool) -> String {
            guard let oldValue else { return "\(label): \(shown(newValue))" }
            if oldValue == newValue { return elideSame ? "\(label): unchanged" : "\(label): \(shown(newValue)) (unchanged)" }
            return "\(label): \(shown(newValue)) (was: \(shown(oldValue)))"
        }
        func pinText(_ config: ProtectedConfig) -> String {
            switch config.bwPin {
            case .signedRelease(let team, let path): return "team \(team) \(path)"
            }
        }
        let header: String
        if old != nil {
            header = "Change vault settings (old values as \"was\")."
        } else if replacesUnreadable {
            header = "A stored item this build cannot read will be replaced."
        } else {
            header = "First setup: there is no previous value."
        }
        func build(elideSame: Bool) -> String {
            var lines = [header]
            lines.append(line("server", new.serverURL.absoluteString, old?.serverURL.absoluteString, elideSame: elideSame))
            lines.append(line("account", new.accountEmail, old?.accountEmail, elideSame: elideSame))
            lines.append(line("organization", new.organizationID, old?.organizationID, elideSame: elideSame))
            lines.append(line("collections", new.collectionIDs.joined(separator: ", "), old?.collectionIDs.joined(separator: ", "), elideSame: elideSame))
            lines.append(line("bw", pinText(new), old.map(pinText), elideSame: elideSame))
            lines.append(line("proxy", new.httpsProxy ?? "none", old.map { $0.httpsProxy ?? "none" }, elideSame: elideSame))
            lines.append(line("CA file", new.nodeExtraCACerts ?? "none", old.map { $0.nodeExtraCACerts ?? "none" }, elideSame: elideSame))
            return lines.joined(separator: "\n")
        }
        // Unchanged values are shown in full while they fit; otherwise only their label stays,
        // so that every NEW value is still on the sheet. Over the budget either way: refused.
        let full = build(elideSame: false)
        if full.utf16.count <= approvalBudget { return full }
        let compact = build(elideSame: true)
        guard compact.utf16.count <= approvalBudget else { throw SetupError.approvalTextTooLong }
        return compact
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
    /// the pin for it. A copy that fails the check leaves the old file untouched. A symbolic link
    /// as the source is followed to the file it points to; the copy is always a regular file and
    /// the source is never changed.
    public static func installBw(from source: String, teamID: String, to destination: String,
                                 signature: BwSignatureChecker) throws -> BwPin {
        guard let resolved = realpath(source, nil) else { throw SetupError.installFailed(reason: "the bw file to copy is missing") }
        let sourcePath = String(cString: resolved)
        free(resolved)
        let input = open(sourcePath, O_RDONLY | O_NOFOLLOW)
        guard input >= 0 else { throw SetupError.installFailed(reason: "the bw file to copy is missing") }
        defer { close(input) }
        var info = stat()
        guard fstat(input, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
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
        let output = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o700)
        guard output >= 0 else { throw SetupError.installFailed(reason: "the bw file could not be copied") }
        var copied = true
        var block = [UInt8](repeating: 0, count: 1 << 16)
        copy: while true {
            let count = read(input, &block, block.count)
            if count < 0 && errno == EINTR { continue }
            if count < 0 { copied = false; break }
            if count == 0 { break }
            var offset = 0
            while offset < count {
                let written = block.withUnsafeBytes { write(output, $0.baseAddress! + offset, count - offset) }
                if written < 0 && errno == EINTR { continue }
                if written <= 0 { copied = false; break copy }
                offset += written
            }
        }
        let closed = close(output) == 0
        guard copied, closed else { throw SetupError.installFailed(reason: "the bw file could not be copied") }
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

    // MARK: profile

    /// Puts a `bw` profile that was logged in and verified under `staged` in place of the live
    /// one, under `bw.lock`. The old profile is removed only after the new one has its name; if
    /// the swap fails the live profile is as it was.
    public static func commitProfile(staged: String, live: String, lockPath: String, timeouts: BwTimeouts) throws {
        let lock: BwLock
        do { lock = try BwLock.acquire(path: lockPath, timeout: timeouts.lockWait) } catch { throw SetupError.bwFailed(step: "lock") }
        defer { lock.release() }
        let backup = live + ".old-" + UUID().uuidString
        let hadLive = FileManager.default.fileExists(atPath: live)
        if hadLive, rename(live, backup) != 0 { throw SetupError.bwFailed(step: "profile") }
        guard rename(staged, live) == 0 else {
            if hadLive { rename(backup, live) }
            throw SetupError.bwFailed(step: "profile")
        }
        if hadLive { try? FileManager.default.removeItem(atPath: backup) }
    }

    /// Removes a staged profile that was not committed. Safe to call when it is already gone.
    public static func discardProfile(staged: String) {
        try? FileManager.default.removeItem(atPath: staged)
    }
}

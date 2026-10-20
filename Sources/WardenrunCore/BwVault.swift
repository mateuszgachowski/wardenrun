import Foundation

/// How wardenrun talks to `bw`. One rung exists so far; doctor and the README report it by name.
public enum BwRung: String, Sendable {
    /// `bw serve` on an inherited socketpair: no password in env or argv, no port, no file.
    case socketpair
}

/// Fetches and creates vault items through one `bw serve` per call (DESIGN 5.2, 5.6).
///
/// Every call holds `bw.lock`, checks the pinned `bw`, runs unlock, sync, list, its work and
/// lock, and ends the process. Nothing stays alive between calls. The master password is passed
/// on as the `SecretBuffer` it is; replies are read as bytes and wiped before the call returns,
/// except the bytes of the one chosen item.
public final class BwVault: @unchecked Sendable {
    private let config: ProtectedConfig
    /// Bitwarden ids are lower-case GUIDs and `bw serve` compares collection ids exactly, so the
    /// ids go to the server in lower case whatever case was typed at setup.
    private let organizationID: String
    private let collectionIDs: [String]
    private let appDataDir: String
    private let home: String
    private let lockPath: String
    private let signature: BwSignatureChecker
    private let timeouts: BwTimeouts
    private let launcherOverride: BwServeLauncher?
    private let state = NSLock()
    private var active: BwServeSession?
    private var cancelled = false

    /// Test hook: sees every reply of every session, before it is wiped. Set before the first call.
    var responseObserver: ((HTTPResponse) -> Void)?

    /// Test seam: builds the launcher from the spec and the environment the vault computed, so a
    /// test can check exactly what the real launcher would receive. Set before the first call.
    var launcherFactory: (BwLaunchSpec, [String: String]) -> BwServeLauncher = {
        BwProcessServeLauncher(spec: $0, environment: $1)
    }

    public init(config: ProtectedConfig, appDataDir: String, home: String, lockPath: String,
                signature: BwSignatureChecker, timeouts: BwTimeouts = .default,
                launcherOverride: BwServeLauncher? = nil) {
        self.config = config
        organizationID = config.organizationID.lowercased()
        collectionIDs = config.collectionIDs.map { $0.lowercased() }
        self.appDataDir = appDataDir
        self.home = home
        self.lockPath = lockPath
        self.signature = signature
        self.timeouts = timeouts
        self.launcherOverride = launcherOverride
    }

    public var rung: BwRung { .socketpair }

    /// Ends the call in progress (or the next one) with `.cancelled`. Thread-safe; permanent.
    public func cancel() {
        let session = state.withLock { () -> BwServeSession? in
            cancelled = true
            return active
        }
        session?.cancel()
    }

    // MARK: fetch

    /// The one item called `itemName` in the allowed collections. The caller wipes it.
    public func fetch(itemName: String) throws -> BwFetchedItem {
        try withUnlockedSession { session in
            let found = try listAllowed(session)
            defer { found.wipeReplies() }
            let ref = try BwItemSelector.select(name: itemName, from: found.hits.map(\.ref),
                                                organizationID: organizationID,
                                                collectionIDs: collectionIDs)
            guard let hit = found.hits.first(where: { $0.ref.id == ref.id }) else {
                throw BwError.protocolError("selected item vanished")
            }
            return try found.copyItem(hit, name: itemName)
        }
    }

    // MARK: create

    /// Creates a login item in the first allowed collection and returns its id. Refuses with
    /// `.alreadyExists` when the name is taken. With `asEnvVariable` the secret is stored as a
    /// hidden custom field `env:<name>` instead of the password (DESIGN 5.6 step 4).
    public func createItem(name: String, username: String?, uri: String?, secret: SecretBuffer,
                           asEnvVariable: String?) throws -> String {
        if let asEnvVariable { try EnvPolicy.validateInjectedName(asEnvVariable) }
        return try withUnlockedSession { session in
            let found = try listAllowed(session)
            defer { found.wipeReplies() }
            do {
                _ = try BwItemSelector.select(name: name, from: found.hits.map(\.ref),
                                              organizationID: organizationID,
                                              collectionIDs: collectionIDs)
                throw BwError.alreadyExists
            } catch BwError.itemNotFound {
                // free to use
            } catch BwError.ambiguous(_) {
                throw BwError.alreadyExists
            }

            let body = try Self.itemDocument(organizationID: organizationID,
                                             collectionID: collectionIDs[0], name: name,
                                             username: username, uri: uri, secret: secret,
                                             asEnvVariable: asEnvVariable)
            defer { body.wipe() }
            let reply = try session.createItem(body)
            defer { reply.wipe() }
            guard let id = reply.body.withUnsafeBytes({ BwReply.createdID($0) }) else {
                throw BwError.protocolError("create reply has no usable id")
            }
            return id
        }
    }

    /// DESIGN 5.6 step 4: type 1, the organization and its first collection, no folder.
    static func itemDocument(organizationID: String, collectionID: String, name: String,
                             username: String?, uri: String?, secret: SecretBuffer,
                             asEnvVariable: String?) throws -> SecretBuffer {
        let uris: [SecretJSONValue] = uri.map { [.object([("match", .null), ("uri", .string($0))])] } ?? []
        let login: SecretJSONValue = .object([
            ("uris", .array(uris)),
            ("username", username.map { .string($0) } ?? .null),
            ("password", asEnvVariable == nil ? .secret(secret) : .null),
            ("totp", .null),
        ])
        let fields: [SecretJSONValue] = asEnvVariable.map {
            [.object([("name", .string("env:" + $0)), ("value", .secret(secret)), ("type", .integer(1))])]
        } ?? []
        return try SecretJSON.encode(.object([
            ("organizationId", .string(organizationID)),
            ("collectionIds", .array([.string(collectionID)])),
            ("folderId", .null),
            ("type", .integer(1)),
            ("name", .string(name)),
            ("notes", .null),
            ("favorite", .bool(false)),
            ("reprompt", .integer(0)),
            ("fields", .array(fields)),
            ("login", login),
        ]))
    }

    // MARK: verify

    /// Unlocks and locks again and reads nothing: `setup` uses it to prove that the stored master
    /// password and the logged-in profile belong together before anything is saved.
    public func verifyLogin() throws {
        try withUnlockedSession(sync: false) { _ in }
    }

    // MARK: session

    private func withUnlockedSession<T>(sync: Bool = true, _ body: (BwServeSession) throws -> T) throws -> T {
        try throwIfCancelled()
        let lock = try acquireLock()
        defer { lock.release() }
        try throwIfCancelled()

        let spec = try BwBinaryPolicy.launchSpec(for: config.bwPin, signature: signature)
        let launcher = launcherOverride ?? launcherFactory(spec, environment(for: spec))
        let session = BwServeSession(launcher: launcher, timeouts: timeouts)
        session.responseObserver = responseObserver
        let alreadyCancelled = state.withLock { () -> Bool in
            active = session
            return cancelled
        }
        // Ends the process and locks the vault first when it was unlocked, on every path out.
        defer {
            state.withLock { active = nil }
            session.close()
        }
        if alreadyCancelled { throw BwError.cancelled }

        try session.start()
        try session.unlock(password: config.masterPassword)
        if sync { try session.sync() }
        return try body(session)
    }

    /// What `bw` gets: nothing of the caller's environment (DESIGN 5.2 rule 3).
    func environment(for spec: BwLaunchSpec) -> [String: String] {
        EnvPolicy.bwEnvironment(home: home, appDataDir: appDataDir, pinnedDirectories: spec.pinnedDirectories,
                                nodeExtraCACerts: config.nodeExtraCACerts, httpsProxy: config.httpsProxy)
    }

    private func throwIfCancelled() throws {
        if state.withLock({ cancelled }) { throw BwError.cancelled }
    }

    /// Polls in short steps so that `cancel()` ends the wait.
    private func acquireLock() throws -> BwLock {
        let deadline = Date().addingTimeInterval(timeouts.lockWait)
        while true {
            try throwIfCancelled()
            do {
                return try BwLock.acquire(path: lockPath, timeout: min(0.25, max(deadline.timeIntervalSinceNow, 0)))
            } catch BwError.lockBusy {
                if Date() >= deadline { throw BwError.lockBusy }
            }
        }
    }

    // MARK: listing

    private struct Hit {
        let ref: BwItemRef
        let reply: HTTPResponse
    }

    /// The list replies of every allowed collection, kept until the caller wipes them, and the
    /// items in them without duplicates (the same item sits in the lists of all its collections).
    private struct Listing {
        var replies: [HTTPResponse] = []
        var hits: [Hit] = []

        func wipeReplies() { for reply in replies { reply.wipe() } }

        /// Only the chosen item's bytes leave the reply, straight into a locked buffer.
        func copyItem(_ hit: Hit, name: String) throws -> BwFetchedItem {
            let range = hit.ref.range
            let source = hit.reply.body
            guard range.lowerBound >= 0, range.upperBound <= source.count else {
                throw BwError.protocolError("malformed list reply")
            }
            let copy = SecretBuffer(count: range.count) { destination in
                source.withUnsafeBytes { bytes in
                    if let from = bytes.baseAddress, let to = destination.baseAddress, range.count > 0 {
                        memcpy(to, from + range.lowerBound, range.count)
                    }
                }
            }
            return BwFetchedItem(itemJSON: copy, id: hit.ref.id, name: name)
        }
    }

    private func listAllowed(_ session: BwServeSession) throws -> Listing {
        var listing = Listing()
        do {
            var seen = Set<String>()
            for collection in collectionIDs {
                let reply = try session.listItems(organizationID: organizationID, collectionID: collection)
                listing.replies.append(reply)
                let refs = try reply.body.withUnsafeBytes { try BwListResponse.parse($0) }
                for ref in refs where seen.insert(ref.id).inserted {
                    listing.hits.append(Hit(ref: ref, reply: reply))
                }
            }
        } catch {
            listing.wipeReplies()
            throw error
        }
        return listing
    }
}

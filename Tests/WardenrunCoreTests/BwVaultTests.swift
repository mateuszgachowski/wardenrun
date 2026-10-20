import Foundation
import Testing
@testable import WardenrunCore

struct BwVaultTests {
    private static let org = "org-1"
    private static let masterPassword = "master-pass-9"
    private static let itemPassword = "gh-secret-1"

    /// Everything a vault needs, in a temp directory: a pinned `bw` file that is never run
    /// (the fake launcher stands in for it), a lock path, a config and the fake server.
    private struct Rig {
        let dir: String
        let bw: String
        let lockPath: String
        let checker: RecordingChecker
        let fake = FakeServe()
        var collections = ["col-a", "col-b"]
        var password = BwVaultTests.masterPassword
        var timeouts = BwTimeouts.default

        init(dir: String, accept: Bool = true) {
            self.dir = dir
            bw = writeFile(dir + "/bin/bw")
            lockPath = dir + "/state/bw.lock"
            checker = RecordingChecker(accept: accept)
            fake.password = BwVaultTests.masterPassword
        }

        func config() throws -> ProtectedConfig {
            try ProtectedConfig(serverURL: URL(string: "https://vault.example")!, accountEmail: "it-user@example.test",
                                organizationID: BwVaultTests.org, collectionIDs: collections,
                                masterPassword: SecretBuffer(copying: Array(password.utf8)),
                                bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: bw),
                                nodeExtraCACerts: "/etc/ca.pem", httpsProxy: "http://proxy.example:3128")
        }

        func vault() throws -> BwVault {
            BwVault(config: try config(), appDataDir: dir + "/appdata", home: dir + "/home", lockPath: lockPath,
                    signature: checker, timeouts: timeouts, launcherOverride: fake)
        }
    }

    private func withRig(accept: Bool = true, _ body: (inout Rig) throws -> Void) throws {
        try withTempDirectory { raw in
            var rig = Rig(dir: realPath(raw), accept: accept)
            try body(&rig)
        }
    }

    private func item(_ id: String, _ name: String, org: String? = BwVaultTests.org, collections: [String] = ["col-a"],
                      deleted: String? = nil, password: String = BwVaultTests.itemPassword,
                      fields: [[String: Any]] = []) -> [String: Any] {
        [
            "object": "item", "id": id, "organizationId": org ?? NSNull(), "folderId": NSNull(), "type": 1,
            "name": name, "notes": NSNull(), "collectionIds": collections, "deletedDate": deleted ?? NSNull(),
            "login": ["username": "octo", "password": password, "uris": [] as [Any], "totp": NSNull()] as [String: Any],
            "fields": fields,
        ]
    }

    private func list(_ items: [[String: Any]]) throws -> String {
        let object: [String: Any] = ["success": true, "data": ["object": "list", "data": items] as [String: Any]]
        return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private func text(_ buffer: SecretBuffer?) -> String? {
        buffer.map { $0.withUnsafeBytes { String(decoding: $0, as: UTF8.self) } }
    }

    private func lockIsFree(_ rig: Rig) -> Bool {
        guard let lock = try? BwLock.acquire(path: rig.lockPath, timeout: 0) else { return false }
        lock.release()
        return true
    }

    private func bodyObject(_ request: FakeServe.Seen?) throws -> [String: Any] {
        let request = try #require(request)
        return try #require(JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
    }

    // MARK: fetch

    @Test func fetchReturnsTheNamedItemsValues() throws {
        try withRig { rig in
            let token: [String: Any] = ["name": "env:IT_TOKEN", "value": "tok-123", "type": 1]
            rig.fake.listBody = try list([item("i1", "it-github", collections: ["col-a"], fields: [token]),
                                          item("i2", "other")])
            let fetched = try rig.vault().fetch(itemName: "it-github")
            #expect(fetched.id == "i1" && fetched.name == "it-github")
            #expect(text(try fetched.value(of: .password)) == Self.itemPassword)
            #expect(text(try fetched.value(of: .username)) == "octo")
            #expect(text(try fetched.value(of: .custom("env:IT_TOKEN"))) == "tok-123")
            let envNames = try fetched.envFieldNames()
            #expect(envNames == ["IT_TOKEN"])
            #expect(rig.fake.log == ["GET /status", "POST /unlock", "POST /sync",
                                     "GET /list/object/items?organizationId=org-1&collectionId=col-a",
                                     "GET /list/object/items?organizationId=org-1&collectionId=col-b",
                                     "POST /lock"])
            #expect(rig.fake.handle?.terminated.value == true)
            #expect(rig.checker.calls == ["LTZ2PFU5D6@" + rig.bw])
            fetched.wipe()
        }
    }

    @Test func idsTypedInUpperCaseReachTheServerInLowerCase() throws {
        try withRig { rig in
            rig.collections = ["COL-A"]
            let upperConfig = try ProtectedConfig(
                serverURL: URL(string: "https://vault.example")!, accountEmail: "it-user@example.test", organizationID: "ORG-1",
                collectionIDs: ["COL-A"], masterPassword: SecretBuffer(copying: Array(rig.password.utf8)),
                bwPin: .signedRelease(teamID: "LTZ2PFU5D6", path: rig.bw))
            rig.fake.listBody = try list([item("i1", "it-x", collections: ["col-a"])])
            let vault = BwVault(config: upperConfig, appDataDir: rig.dir + "/appdata", home: rig.dir + "/home",
                                lockPath: rig.lockPath, signature: rig.checker, timeouts: rig.timeouts, launcherOverride: rig.fake)
            let fetched = try vault.fetch(itemName: "it-x")
            #expect(rig.fake.log.contains("GET /list/object/items?organizationId=org-1&collectionId=col-a"))
            fetched.wipe()
        }
    }

    @Test func fetchPicksOnlyTheAllowedCollections() throws {
        try withRig { rig in
            rig.collections = ["col-a"]
            // The server's own filter is only a first cut: an item of another collection can come back.
            rig.fake.listBody = try list([item("i1", "it-x", collections: ["col-other"]),
                                          item("i2", "it-y", org: "org-other", collections: ["col-a"])])
            let vault = try rig.vault()
            #expect(throws: BwError.itemNotFound) { _ = try vault.fetch(itemName: "it-x") }
            #expect(throws: BwError.itemNotFound) { _ = try vault.fetch(itemName: "it-y") }
            #expect(rig.fake.log.filter { $0.hasPrefix("GET /list") }
                == Array(repeating: "GET /list/object/items?organizationId=org-1&collectionId=col-a", count: 2))
        }
    }

    @Test func oneItemInTwoAllowedCollectionsIsNotAmbiguous() throws {
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "it-both", collections: ["col-a", "col-b"])])
            let fetched = try rig.vault().fetch(itemName: "it-both")
            #expect(fetched.id == "i1")
            #expect(rig.fake.log.filter { $0.hasPrefix("GET /list") }.count == 2)
            fetched.wipe()
        }
    }

    @Test func itemsFromDifferentCollectionListsAreAllConsidered() throws {
        try withRig { rig in
            rig.fake.listByCollection["col-a"] = try list([item("i1", "first", collections: ["col-a"])])
            rig.fake.listByCollection["col-b"] = try list([item("i2", "second", collections: ["col-b"])])
            let fetched = try rig.vault().fetch(itemName: "second")
            #expect(fetched.id == "i2")
            #expect(text(try fetched.value(of: .password)) == Self.itemPassword)
            fetched.wipe()
        }
    }

    @Test func everyResponseIsWipedWhenFetchReturns() throws {
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "it-github"), item("i2", "it-other", password: "other-secret")])
            let vault = try rig.vault()
            let seen = Box<[HTTPResponse]>([])
            vault.responseObserver = { seen.value.append($0) }
            let fetched = try vault.fetch(itemName: "it-github")
            // status, unlock, sync, two lists, lock
            #expect(seen.value.count == 6)
            #expect(seen.value.allSatisfy { $0.body.isWiped })
            #expect(text(try fetched.value(of: .password)) == Self.itemPassword)
            fetched.wipe()
        }
    }

    @Test func notFoundAndAmbiguousMapToBwError() throws {
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "it-dup"), item("i2", "it-dup"), item("i3", "it-trashed", deleted: "2026-01-01T00:00:00Z")])
            let vault = try rig.vault()
            #expect(throws: BwError.ambiguous(count: 2)) { _ = try vault.fetch(itemName: "it-dup") }
            #expect(throws: BwError.itemNotFound) { _ = try vault.fetch(itemName: "missing") }
            #expect(throws: BwError.itemNotFound) { _ = try vault.fetch(itemName: "it-trashed") }
        }
    }

    // MARK: lock and cleanup

    @Test func lockBusyWhenAnotherFetchHoldsTheLock() throws {
        try withRig { rig in
            rig.timeouts.lockWait = 0.3
            let held = try BwLock.acquire(path: rig.lockPath, timeout: 1)
            let vault = try rig.vault()
            #expect(throws: BwError.lockBusy) { _ = try vault.fetch(itemName: "x") }
            #expect(rig.fake.handles.value.isEmpty)
            #expect(rig.checker.calls.isEmpty)
            held.release()
            rig.fake.listBody = try list([item("i1", "x")])
            let fetched = try vault.fetch(itemName: "x")
            fetched.wipe()
        }
    }

    @Test func lockIsReleasedAfterSuccessAndAfterEachFailure() throws {
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "present")])
            let vault = try rig.vault()
            try vault.fetch(itemName: "present").wipe()
            #expect(lockIsFree(rig))
            #expect(throws: BwError.itemNotFound) { _ = try vault.fetch(itemName: "absent") }
            #expect(lockIsFree(rig))
            rig.fake.overrides["GET /list/object/items"] = "HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}"
            #expect(throws: BwError.serverError(status: 500)) { _ = try vault.fetch(itemName: "present") }
            #expect(lockIsFree(rig))
        }
        try withRig { rig in
            rig.password = "not the password"
            #expect(throws: BwError.unlockFailed(message: "Invalid master password.")) { _ = try rig.vault().fetch(itemName: "x") }
            #expect(lockIsFree(rig))
        }
        try withRig(accept: false) { rig in
            #expect(throws: BwError.signatureMismatch) { _ = try rig.vault().fetch(itemName: "x") }
            #expect(rig.fake.handles.value.isEmpty)
            #expect(lockIsFree(rig))
        }
    }

    @Test func aMissingBwIsRefusedBeforeAnythingIsLaunched() throws {
        try withRig { rig in
            try FileManager.default.removeItem(atPath: rig.bw)
            let vault = try rig.vault()
            do {
                _ = try vault.fetch(itemName: "x")
                Issue.record("fetch succeeded")
            } catch BwError.binaryNotAllowed(_) {
            }
            #expect(rig.fake.handles.value.isEmpty)
            #expect(lockIsFree(rig))
        }
    }

    @Test func sessionIsClosedOnUnlockListAndParseFailures() throws {
        try withRig { rig in
            rig.password = "not the password"
            #expect(throws: BwError.unlockFailed(message: "Invalid master password.")) { _ = try rig.vault().fetch(itemName: "x") }
            #expect(rig.fake.handle?.terminated.value == true)
            #expect(!rig.fake.log.contains("POST /lock"))
        }
        try withRig { rig in
            rig.fake.overrides["GET /list/object/items"] = "HTTP/1.1 500 Oops\r\nContent-Length: 2\r\n\r\n{}"
            #expect(throws: BwError.serverError(status: 500)) { _ = try rig.vault().fetch(itemName: "x") }
            #expect(rig.fake.handle?.terminated.value == true)
            #expect(rig.fake.log.last == "POST /lock")
        }
        try withRig { rig in
            rig.fake.listBody = "{\"success\":true,\"data\":{\"data\":\"not a list\"}}"
            #expect(throws: BwError.protocolError("list reply has no data")) { _ = try rig.vault().fetch(itemName: "x") }
            #expect(rig.fake.handle?.terminated.value == true)
            #expect(rig.fake.log.last == "POST /lock")
        }
    }

    @Test func malformedServerRepliesNeverLeakTheirContentIntoErrors() throws {
        let leaks = [Self.masterPassword, Self.itemPassword]
        let replies = [
            "{\"success\":true,\"data\":\"\(Self.masterPassword) \(Self.itemPassword)\"}",
            "{\"success\":false,\"message\":\"\(Self.masterPassword) \(Self.itemPassword)\"}",
            "\(Self.masterPassword) \(Self.itemPassword) [[[",
            "{\"success\":true,\"data\":{\"data\":[{\"id\":\"\(Self.itemPassword)\",\"name\":\"\(Self.masterPassword)\"}",
        ]
        for body in replies {
            try withRig { rig in
                rig.fake.listBody = body
                do {
                    _ = try rig.vault().fetch(itemName: "x")
                    Issue.record("fetch succeeded on \(body.count) bytes")
                } catch {
                    let shown = String(describing: error) + String(reflecting: error) + "\(error)"
                    for secret in leaks { #expect(!shown.contains(secret), "error shows \(secret)") }
                }
            }
        }
        // The same for a refused unlock whose reply carries the password and an item password.
        try withRig { rig in
            let body = "{\"success\":false,\"message\":\"\(Self.masterPassword) \(Self.itemPassword)\"}"
            rig.fake.overrides["POST /unlock"] = "HTTP/1.1 502 Bad\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body
            do {
                _ = try rig.vault().fetch(itemName: "x")
                Issue.record("fetch succeeded")
            } catch {
                let shown = String(describing: error) + String(reflecting: error)
                for secret in leaks { #expect(!shown.contains(secret)) }
            }
        }
    }

    @Test func masterPasswordIsNotInAnyRequestBesidesUnlock() throws {
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "it-github")])
            try rig.vault().fetch(itemName: "it-github").wipe()
            _ = try rig.vault().createItem(name: "fresh", username: nil, uri: nil,
                                          secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
            let unlock = try #require(rig.fake.seen.first { $0.target == "/unlock" })
            #expect(String(decoding: unlock.body, as: UTF8.self).contains(Self.masterPassword))
            for request in rig.fake.seen where request.target != "/unlock" {
                let shown = request.target + String(decoding: request.body, as: UTF8.self)
                #expect(!shown.contains(Self.masterPassword))
            }
        }
    }

    // MARK: create

    @Test func createItemSendsTheDocumentedBody() throws {
        try withRig { rig in
            let id = try rig.vault().createItem(name: "new-thing", username: "bob", uri: "https://x.example/a b",
                                               secret: SecretBuffer(copying: Array("pw-123456".utf8)),
                                               asEnvVariable: nil)
            #expect(id == "new-item-id")
            #expect(rig.fake.log == ["GET /status", "POST /unlock", "POST /sync",
                                     "GET /list/object/items?organizationId=org-1&collectionId=col-a",
                                     "GET /list/object/items?organizationId=org-1&collectionId=col-b",
                                     "POST /object/item", "POST /lock"])
            let body = try bodyObject(rig.fake.seen.first { $0.target == "/object/item" })
            #expect(body["type"] as? Int == 1)
            #expect(body["organizationId"] as? String == Self.org)
            #expect(body["collectionIds"] as? [String] == ["col-a"])
            #expect(body["folderId"] is NSNull)
            #expect(body["name"] as? String == "new-thing")
            #expect(body["fields"] as? [Any] != nil && (body["fields"] as? [Any])?.isEmpty == true)
            let login = try #require(body["login"] as? [String: Any])
            #expect(login["username"] as? String == "bob")
            #expect(login["password"] as? String == "pw-123456")
            let uris = try #require(login["uris"] as? [[String: Any]])
            #expect(uris.count == 1 && uris[0]["uri"] as? String == "https://x.example/a b")
        }
    }

    @Test func createItemWithAnEnvironmentVariableStoresAHiddenCustomField() throws {
        try withRig { rig in
            _ = try rig.vault().createItem(name: "env-thing", username: nil, uri: nil,
                                          secret: SecretBuffer(copying: Array("pw-123456".utf8)),
                                          asEnvVariable: "API_KEY")
            let body = try bodyObject(rig.fake.seen.first { $0.target == "/object/item" })
            let login = try #require(body["login"] as? [String: Any])
            #expect(login["password"] is NSNull)
            #expect(login["username"] is NSNull)
            #expect((login["uris"] as? [Any])?.isEmpty == true)
            let fields = try #require(body["fields"] as? [[String: Any]])
            #expect(fields.count == 1)
            #expect(fields[0]["name"] as? String == "env:API_KEY")
            #expect(fields[0]["value"] as? String == "pw-123456")
            #expect(fields[0]["type"] as? Int == 1)
        }
    }

    @Test func createItemRefusesAnExistingNameWithoutPosting() throws {
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "it-github")])
            let vault = try rig.vault()
            #expect(throws: BwError.alreadyExists) {
                _ = try vault.createItem(name: "it-github", username: nil, uri: nil,
                                         secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
            }
            #expect(!rig.fake.log.contains("POST /object/item"))
            #expect(rig.fake.handle?.terminated.value == true)
            #expect(lockIsFree(rig))
        }
        try withRig { rig in
            // two items of that name is "taken" as well; a trashed one is not
            rig.fake.listBody = try list([item("i1", "dup"), item("i2", "dup"), item("i3", "gone", deleted: "2026-01-01T00:00:00Z")])
            let vault = try rig.vault()
            #expect(throws: BwError.alreadyExists) {
                _ = try vault.createItem(name: "dup", username: nil, uri: nil,
                                         secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
            }
            let id = try vault.createItem(name: "gone", username: nil, uri: nil,
                                          secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
            #expect(id == "new-item-id")
        }
    }

    @Test func createItemKeepsOnlyTheIdAndWipesTheReply() throws {
        try withRig { rig in
            let vault = try rig.vault()
            let seen = Box<[HTTPResponse]>([])
            vault.responseObserver = { seen.value.append($0) }
            let id = try vault.createItem(name: "fresh", username: nil, uri: nil,
                                          secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
            #expect(id == "new-item-id")
            #expect(seen.value.count == 7)   // status, unlock, sync, two lists, create, lock
            #expect(seen.value.allSatisfy { $0.body.isWiped })
            #expect(!id.contains("ECHOED"))
        }
    }

    @Test func createItemRejectsAReplyWithoutAUsableIdAndAServerError() throws {
        let bad = ["{\"success\":true,\"data\":{\"object\":\"item\"}}",
                   "{\"success\":true,\"data\":{\"id\":\"has space\"}}",
                   "{\"success\":true,\"data\":{\"id\":\"\(String(repeating: "a", count: 65))\"}}",
                   "{\"success\":true,\"data\":{\"id\":\"line\\nbreak\"}}"]
        for body in bad {
            try withRig { rig in
                rig.fake.overrides["POST /object/item"] = "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n" + body
                #expect(throws: BwError.protocolError("create reply has no usable id")) {
                    _ = try rig.vault().createItem(name: "n", username: nil, uri: nil,
                                                   secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
                }
                #expect(rig.fake.handle?.terminated.value == true)
            }
        }
        try withRig { rig in
            rig.fake.overrides["POST /object/item"] = "HTTP/1.1 400 Bad\r\nContent-Length: 2\r\n\r\n{}"
            #expect(throws: BwError.serverError(status: 400)) {
                _ = try rig.vault().createItem(name: "n", username: nil, uri: nil,
                                               secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: nil)
            }
        }
    }

    @Test func createItemRefusesAVariableNameThatCouldNotBeInjectedLater() throws {
        try withRig { rig in
            let vault = try rig.vault()
            for name in ["1BAD", "DYLD_INSERT_LIBRARIES", "a-b", ""] {
                #expect(throws: EnvPolicyError.self, "\(name)") {
                    _ = try vault.createItem(name: "n", username: nil, uri: nil,
                                             secret: SecretBuffer(copying: Array("pw-123456".utf8)), asEnvVariable: name)
                }
            }
            #expect(rig.fake.handles.value.isEmpty)
        }
    }

    // MARK: cancel, rung, environment

    @Test func cancelFromAnotherThreadAbortsFetch() throws {
        try withRig { rig in
            rig.fake.overrides["POST /sync"] = "SILENT"
            let vault = try rig.vault()
            afterDelay(0.3) { vault.cancel() }
            let start = Date()
            #expect(throws: BwError.cancelled) { _ = try vault.fetch(itemName: "x") }
            #expect(Date().timeIntervalSince(start) < 10)
            #expect(rig.fake.handle?.terminated.value == true)
            #expect(lockIsFree(rig))
            // once cancelled, always cancelled
            #expect(throws: BwError.cancelled) { _ = try vault.fetch(itemName: "x") }
        }
    }

    @Test func cancelWhileWaitingForTheLockEndsTheWait() throws {
        try withRig { rig in
            rig.timeouts.lockWait = 30
            let held = try BwLock.acquire(path: rig.lockPath, timeout: 1)
            defer { held.release() }
            let vault = try rig.vault()
            afterDelay(0.3) { vault.cancel() }
            let start = Date()
            #expect(throws: BwError.cancelled) { _ = try vault.fetch(itemName: "x") }
            #expect(Date().timeIntervalSince(start) < 10)
        }
    }

    @Test func rungIsSocketpair() throws {
        try withRig { rig in
            let vault = try rig.vault()
            #expect(vault.rung == .socketpair)
            #expect(BwRung.socketpair.rawValue == "socketpair")
        }
    }

    @Test func theLauncherReceivesExactlyTheAllowlistedEnvironmentNotTheCallers() throws {
        setenv("BW_SESSION", "leaked-session", 1)
        setenv("NODE_OPTIONS", "--require /evil.js", 1)
        defer { unsetenv("BW_SESSION"); unsetenv("NODE_OPTIONS") }
        try withRig { rig in
            rig.fake.listBody = try list([item("i1", "x")])
            let vault = BwVault(config: try rig.config(), appDataDir: rig.dir + "/appdata", home: rig.dir + "/home",
                                lockPath: rig.lockPath, signature: rig.checker, timeouts: rig.timeouts)
            let seen = Box<[(BwLaunchSpec, [String: String])]>([])
            let fake = rig.fake
            vault.launcherFactory = { spec, environment in
                seen.value.append((spec, environment))
                return fake
            }
            try vault.fetch(itemName: "x").wipe()
            let (spec, environment) = try #require(seen.value.first)
            #expect(seen.value.count == 1)
            #expect(spec.executable == rig.bw)
            let expected = EnvPolicy.bwEnvironment(home: rig.dir + "/home", appDataDir: rig.dir + "/appdata",
                                                   pinnedDirectories: [rig.dir + "/bin"], nodeExtraCACerts: "/etc/ca.pem",
                                                   httpsProxy: "http://proxy.example:3128")
            #expect(environment == expected)
            #expect(environment["BW_SESSION"] == nil && environment["NODE_OPTIONS"] == nil)
        }
    }

    @Test func theBwEnvironmentCarriesTheConfigAndNothingInherited() throws {
        try withRig { rig in
            let vault = try rig.vault()
            let spec = BwLaunchSpec(executable: rig.bw, leadingArguments: [], pinnedDirectories: [rig.dir + "/bin"])
            let environment = vault.environment(for: spec)
            #expect(environment["NODE_EXTRA_CA_CERTS"] == "/etc/ca.pem")
            #expect(environment["https_proxy"] == "http://proxy.example:3128")
            #expect(environment["BITWARDENCLI_APPDATA_DIR"] == rig.dir + "/appdata")
            #expect(environment["HOME"] == rig.dir + "/home")
            #expect(environment["PATH"] == rig.dir + "/bin")
            #expect(environment["BW_SESSION"] == nil && environment["NODE_OPTIONS"] == nil)
        }
    }
}

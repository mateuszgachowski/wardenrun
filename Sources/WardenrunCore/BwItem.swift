import Foundation

/// What is known about one item of a `bw` list reply, without its secret values.
///
/// `range` is the byte range of the item object inside the reply body, so that the chosen
/// item can be copied out and every other item left behind in the buffer that gets wiped.
public struct BwItemRef: Equatable, Sendable {
    public let id: String
    public let name: String
    public let organizationID: String?
    public let collectionIDs: [String]
    public let isDeleted: Bool
    public let range: Range<Int>
}

func isKey(_ key: [UInt8], _ word: StaticString) -> Bool {
    key.count == word.utf8CodeUnitCount && word.withUTF8Buffer { key.elementsEqual($0) }
}

/// Reads the vault-management reply to `list items`:
/// `{"success":true,"data":{"object":"list","data":[ {item}, ... ]}}`.
///
/// Only an item's id, name, organization, collection ids and deleted flag become `String`s.
/// Everything else, including every password, stays where it is, in the reply buffer.
public enum BwListResponse {
    public static func parse(_ body: UnsafeRawBufferPointer) throws -> [BwItemRef] {
        do {
            return try parseEnvelope(body)
        } catch is JSONError {
            // The error never quotes the reply: it may hold secrets.
            throw BwError.protocolError("malformed list reply")
        }
    }

    private static func parseEnvelope(_ body: UnsafeRawBufferPointer) throws -> [BwItemRef] {
        var cursor = JSONCursor(body)
        var success: Bool?
        var refs: [BwItemRef]?
        try cursor.members { key, value in
            if isKey(key, "success") {
                if try value.kind() == .bool { success = try value.bool() } else { try value.skipValue() }
            } else if isKey(key, "data"), try value.kind() == .object {
                try value.members { innerKey, inner in
                    guard isKey(innerKey, "data"), try inner.kind() == .array else {
                        try inner.skipValue()
                        return
                    }
                    var found: [BwItemRef] = []
                    try inner.elements { _, element in
                        var probe = element
                        let range = try probe.skipValue()
                        if try element.kind() == .object {
                            if let ref = try readItem(&element, range: range) { found.append(ref) }
                        } else {
                            try element.skipValue()
                        }
                    }
                    refs = found
                }
            } else {
                try value.skipValue()
            }
        }
        try cursor.finish()
        guard success == true else { throw BwError.protocolError("list reply was not a success") }
        guard let refs else { throw BwError.protocolError("list reply has no data") }
        return refs
    }

    private static func readItem(_ element: inout JSONCursor, range: Range<Int>) throws -> BwItemRef? {
        var id: String?, name: String?, organization: String?
        var collections: [String] = []
        var deleted = false
        try element.members { key, value in
            if isKey(key, "id") {
                id = try optionalString(&value)
            } else if isKey(key, "name") {
                name = try optionalString(&value)
            } else if isKey(key, "organizationId") {
                organization = try optionalString(&value)
            } else if isKey(key, "collectionIds"), try value.kind() == .array {
                try value.elements { _, entry in
                    if let text = try optionalString(&entry) { collections.append(text) }
                }
            } else if isKey(key, "deletedDate") {
                deleted = try value.kind() != .null
                try value.skipValue()
            } else {
                try value.skipValue()
            }
        }
        // An item without a readable id or name cannot be chosen, so it is left out.
        guard let id, let name else { return nil }
        return BwItemRef(id: id, name: name, organizationID: organization, collectionIDs: collections,
                         isDeleted: deleted, range: range)
    }

    private static func optionalString(_ cursor: inout JSONCursor) throws -> String? {
        guard try cursor.kind() == .string else {
            try cursor.skipValue()
            return nil
        }
        return String(decoding: try cursor.string(), as: UTF8.self)
    }
}

/// Picks the one item wardenrun was asked for. The server's own filters are only a first cut:
/// `--collectionid` filters are OR, and `get` would match fuzzily, so the decision is made here.
public enum BwItemSelector {
    /// Exactly one item must have this name (compared byte for byte, so case, spaces and
    /// Unicode normalisation all matter), not be in the trash, belong to `organizationID`, and
    /// sit in at least one of `collectionIDs`.
    public static func select(name: String, from refs: [BwItemRef], organizationID: String,
                              collectionIDs: [String]) throws -> BwItemRef {
        let wanted = Array(name.utf8)
        let allowed = Set(collectionIDs)
        let matches = refs.filter { ref in
            !ref.isDeleted
                && ref.organizationID == organizationID
                && !allowed.isDisjoint(with: ref.collectionIDs)
                && Array(ref.name.utf8) == wanted
        }
        switch matches.count {
        case 0: throw BwError.itemNotFound
        case 1: return matches[0]
        default: throw BwError.ambiguous(count: matches.count)
        }
    }
}

/// A value the caller can ask for: a login field or the name of a custom field (DESIGN 5.4).
/// `totp` is not supported yet; it would hand out the stored seed instead of a code.
public enum BwFieldSpec: Equatable, Sendable {
    case password, username, notes, uri
    case custom(String)

    public init(parsing text: String) throws {
        switch text {
        case "password": self = .password
        case "username": self = .username
        case "notes": self = .notes
        case "uri": self = .uri
        case "totp": throw BwError.unsupportedField("totp")
        default:
            guard !text.isEmpty, !text.utf8.contains(where: { $0 < 0x20 || $0 == 0x7F }) else {
                throw BwError.unsupportedField(text)
            }
            self = .custom(text)
        }
    }
}

/// The one chosen item, kept as its JSON bytes in locked memory. Values are unescaped from
/// those bytes straight into `SecretBuffer`s when asked for, so no secret is ever a `String`.
public final class BwFetchedItem: @unchecked Sendable {
    public let id: String
    public let name: String
    private let itemJSON: SecretBuffer

    public init(itemJSON: SecretBuffer, id: String, name: String) {
        self.itemJSON = itemJSON
        self.id = id
        self.name = name
    }

    var isWipedForTesting: Bool { itemJSON.isWiped }

    /// The wanted value, or nil when the item does not have it (absent, null or an empty list).
    /// A custom field name that occurs twice yields the first one.
    public func value(of field: BwFieldSpec) throws -> SecretBuffer? {
        guard !itemJSON.isWiped else { throw BwError.protocolError("item already wiped") }
        do {
            return try itemJSON.withUnsafeBytes { try Self.extract(field, from: $0) }
        } catch is JSONError {
            throw BwError.protocolError("malformed item")
        }
    }

    /// Names `VAR` of the custom fields called `env:VAR` (DESIGN 5.4). Not validated here; the
    /// caller checks them with `EnvPolicy.validateInjectedName`.
    public var envFieldNames: [String] {
        guard !itemJSON.isWiped else { return [] }
        let prefix = Array("env:".utf8)
        var names: [String] = []
        _ = try? itemJSON.withUnsafeBytes { raw in
            var cursor = JSONCursor(raw)
            try cursor.members { key, value in
                guard isKey(key, "fields"), try value.kind() == .array else {
                    try value.skipValue()
                    return
                }
                try value.elements { _, element in
                    guard try element.kind() == .object else {
                        try element.skipValue()
                        return
                    }
                    try element.members { fieldKey, fieldValue in
                        if isKey(fieldKey, "name"), try fieldValue.kind() == .string {
                            let fieldName = try fieldValue.string()
                            if fieldName.starts(with: prefix) {
                                names.append(String(decoding: fieldName.dropFirst(prefix.count), as: UTF8.self))
                            }
                        } else {
                            try fieldValue.skipValue()
                        }
                    }
                }
            }
        }
        return names
    }

    public func wipe() { itemJSON.wipe() }

    // MARK: extraction

    private static func secretOrNil(_ cursor: inout JSONCursor) throws -> SecretBuffer? {
        guard try cursor.kind() == .string else {
            try cursor.skipValue()
            return nil
        }
        return try cursor.secretString()
    }

    private static func extract(_ field: BwFieldSpec, from raw: UnsafeRawBufferPointer) throws -> SecretBuffer? {
        var cursor = JSONCursor(raw)
        var result: SecretBuffer?
        switch field {
        case .password, .username:
            try cursor.members { key, value in
                guard isKey(key, "login"), try value.kind() == .object else {
                    try value.skipValue()
                    return
                }
                try value.members { loginKey, loginValue in
                    if field == .password ? isKey(loginKey, "password") : isKey(loginKey, "username") {
                        result = try secretOrNil(&loginValue)
                    } else {
                        try loginValue.skipValue()
                    }
                }
            }
        case .notes:
            try cursor.members { key, value in
                if isKey(key, "notes") { result = try secretOrNil(&value) } else { try value.skipValue() }
            }
        case .uri:
            try cursor.members { key, value in
                guard isKey(key, "login"), try value.kind() == .object else {
                    try value.skipValue()
                    return
                }
                try value.members { loginKey, loginValue in
                    guard isKey(loginKey, "uris"), try loginValue.kind() == .array else {
                        try loginValue.skipValue()
                        return
                    }
                    try loginValue.elements { position, uriEntry in
                        guard position == 0, try uriEntry.kind() == .object else {
                            try uriEntry.skipValue()
                            return
                        }
                        try uriEntry.members { uriKey, uriValue in
                            if isKey(uriKey, "uri") { result = try secretOrNil(&uriValue) } else { try uriValue.skipValue() }
                        }
                    }
                }
            }
        case .custom(let wanted):
            let wantedBytes = Array(wanted.utf8)
            try cursor.members { key, value in
                guard isKey(key, "fields"), try value.kind() == .array else {
                    try value.skipValue()
                    return
                }
                try value.elements { _, element in
                    guard try element.kind() == .object else {
                        try element.skipValue()
                        return
                    }
                    var fieldName: [UInt8]?
                    var valueCursor: JSONCursor?
                    try element.members { fieldKey, fieldValue in
                        if isKey(fieldKey, "name"), try fieldValue.kind() == .string {
                            fieldName = try fieldValue.string()
                        } else if isKey(fieldKey, "value") {
                            valueCursor = fieldValue
                            try fieldValue.skipValue()
                        } else {
                            try fieldValue.skipValue()
                        }
                    }
                    if result == nil, fieldName == wantedBytes, var probe = valueCursor {
                        result = try secretOrNil(&probe)
                    }
                }
            }
        }
        return result
    }
}

import Testing
@testable import WardenrunCore

struct BwErrorTests {
    private let everyCase: [BwError] = [
        .itemNotFound, .ambiguous(count: 2), .alreadyExists,
        .unsupportedField("totp"), .binaryNotAllowed(reason: "symlink"),
        .signatureMismatch, .lockBusy, .cancelled, .outputTooLarge, .notLoggedIn,
        .spawnFailed(errno: 2), .timeout(phase: "unlock"), .protocolError("no content-length"),
        .unlockFailed(message: "Invalid master password."), .serverError(status: 500),
        .invalidUTF8(field: "password"),
    ]

    @Test func errorCasesCarryOnlyStringsAndIntegers() {
        for error in everyCase {
            for child in Mirror(reflecting: error).children {
                // A labelled payload arrives as a one-element tuple; look inside it.
                let inner = Mirror(reflecting: child.value)
                let payloads = inner.displayStyle == .tuple ? inner.children.map(\.value) : [child.value]
                for payload in payloads {
                    #expect(payload is String || payload is Int || payload is Int32,
                            "\(error) carries a \(type(of: payload))")
                }
            }
        }
    }

    @Test func theCheckSeesThroughLabelledPayloads() {
        // Guards the test above: it must actually find the payloads it vouches for.
        var payloadCount = 0
        for error in everyCase {
            for child in Mirror(reflecting: error).children {
                let inner = Mirror(reflecting: child.value)
                payloadCount += inner.displayStyle == .tuple ? inner.children.count : 1
            }
        }
        #expect(payloadCount == 9)   // the nine cases that carry a payload
    }

    @Test func errorsAreEquatable() {
        #expect(BwError.ambiguous(count: 2) == BwError.ambiguous(count: 2))
        #expect(BwError.ambiguous(count: 2) != BwError.ambiguous(count: 3))
        #expect(BwError.itemNotFound != BwError.alreadyExists)
    }
}

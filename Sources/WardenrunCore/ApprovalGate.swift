import Foundation

public enum GateRefusal: Error, Equatable, Sendable {
    /// Another wardenrun is showing its sheet right now.
    case anotherApprovalPending
    /// Too many recent denials or timeouts.
    case lockedOut(secondsLeft: Int)
    /// The state directory cannot be used, so the limit cannot be applied; nothing is asked.
    case stateUnavailable
}

/// The rules around asking a human (DESIGN 5.3, threat 10): one sheet at a time, and a short
/// lock-out after repeated denials or timeouts.
///
/// wardenrun is a one-shot process, so both rules live in a small directory: a `flock` file for
/// the pending sheet and a state file with the times of recent failures. This wears down a
/// pestering agent; it is not a barrier against one that can delete the files (same user).
public final class ApprovalGate: @unchecked Sendable {
    private let directory: String
    private let now: @Sendable () -> Date
    private let window: TimeInterval
    private let maxFailures: Int
    private let lockout: TimeInterval

    public init(stateDirectory: String, now: @escaping @Sendable () -> Date = { Date() },
                window: TimeInterval = 300, maxFailures: Int = 3, lockout: TimeInterval = 60) {
        directory = stateDirectory
        self.now = now
        self.window = window
        self.maxFailures = maxFailures
        self.lockout = lockout
    }

    private struct State {
        var failures: [Double] = []
        var lockedUntil: Double = 0
    }

    /// Runs `ask` while holding the pending-sheet lock. Refuses at once when another sheet is
    /// open or a lock-out is on; otherwise returns what `ask` decided, after counting a denial or
    /// a timeout. `.unavailable` and `.approved` are not counted (and an approval clears nothing).
    public func guarded(_ ask: () -> ApprovalDecision) throws -> ApprovalDecision {
        let descriptor = try openLock()
        defer {
            flock(descriptor, LOCK_UN)
            close(descriptor)
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            if errno == EWOULDBLOCK { throw GateRefusal.anotherApprovalPending }
            throw GateRefusal.stateUnavailable
        }

        let statePath = directory + "/approval-state.json"
        var state = Self.read(statePath)
        let start = now().timeIntervalSince1970
        // A state file is just a file. A lock-out further away than one lock-out can last is not
        // one this code wrote: it is ignored (and a file that is deleted lifts the limit anyway).
        if state.lockedUntil > start + lockout { state.lockedUntil = 0 }
        if state.lockedUntil > start {
            throw GateRefusal.lockedOut(secondsLeft: Int((state.lockedUntil - start).rounded(.up)))
        }
        state.failures = state.failures.filter { start - $0 < window && $0 <= start }
        // If the limit cannot be remembered, nothing is asked: a state that cannot be written
        // would otherwise switch the lock-out off.
        guard Self.write(state, to: statePath) else { throw GateRefusal.stateUnavailable }

        let decision = ask()
        switch decision {
        case .denied, .timedOut:
            let at = now().timeIntervalSince1970
            state.failures.append(at)
            if state.failures.count >= maxFailures {
                state.lockedUntil = at + lockout
                state.failures = []
            }
        case .approved, .unavailable:
            break
        }
        Self.write(state, to: statePath)
        return decision
    }

    private func openLock() throws -> Int32 {
        if !FileManager.default.fileExists(atPath: directory) {
            do {
                try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
            } catch {
                throw GateRefusal.stateUnavailable
            }
        }
        let descriptor = open(directory + "/approval.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw GateRefusal.stateUnavailable }
        return descriptor
    }

    private static func read(_ path: String) -> State {
        guard let data = FileManager.default.contents(atPath: path),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let failures = object["failures"] as? [Double], failures.allSatisfy({ $0.isFinite }),
              let lockedUntil = object["locked_until"] as? Double, lockedUntil.isFinite else { return State() }
        return State(failures: failures, lockedUntil: lockedUntil)
    }

    /// Atomic replace, mode 0600; the temporary name is removed first and created exclusively
    /// without following links. Returns whether the state is now on disk.
    @discardableResult
    private static func write(_ state: State, to path: String) -> Bool {
        let object: [String: Any] = ["failures": state.failures, "locked_until": state.lockedUntil]
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return false }
        let temporary = path + ".tmp"
        unlink(temporary)
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { return false }
        let written = data.withUnsafeBytes { Foundation.write(descriptor, $0.baseAddress, $0.count) }
        close(descriptor)
        guard written == data.count, rename(temporary, path) == 0 else { unlink(temporary); return false }
        return true
    }
}

extension GateRefusal {
    /// One fixed sentence per refusal; only the number of seconds varies.
    public var message: String {
        switch self {
        case .anotherApprovalPending: return "another approval is waiting for an answer right now"
        case .lockedOut(let seconds): return "too many refused approvals; try again in \(seconds) second\(seconds == 1 ? "" : "s")"
        case .stateUnavailable: return "the approval state directory cannot be used, so nothing was asked"
        }
    }
}

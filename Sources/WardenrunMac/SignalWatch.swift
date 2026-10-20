#if canImport(Darwin)
import Darwin
import Foundation

/// Watches for HUP, INT and TERM while wardenrun talks to `bw` and prepares a run, so that an
/// interrupt ends the `bw` session (and locks the vault) instead of killing wardenrun and leaving
/// an unlocked `bw serve` behind. Once the command has started, `ChildRunner` takes the signals
/// over. `stop()` puts the previous handlers back and may be called any number of times.
final class SignalWatch: @unchecked Sendable {
    static let defaultSignals: [Int32] = [SIGHUP, SIGINT, SIGTERM]

    private let lock = NSLock()
    private var sources: [DispatchSourceSignal] = []
    private var previous: [(signal: Int32, action: sigaction)] = []
    private var firedSignal: Int32?
    private var stopped = false
    private let queue = DispatchQueue(label: "wardenrun.signalwatch")

    /// `onSignal` runs on a private queue, once per delivered signal.
    init(signals: [Int32] = SignalWatch.defaultSignals, onSignal: @escaping @Sendable (Int32) -> Void) {
        for number in signals {
            var old = sigaction()
            var ignore = sigaction()
            ignore.__sigaction_u.__sa_handler = SIG_IGN
            sigemptyset(&ignore.sa_mask)
            sigaction(number, &ignore, &old)
            previous.append((number, old))

            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { [weak self] in
                self?.lock.lock()
                if self?.firedSignal == nil { self?.firedSignal = number }
                self?.lock.unlock()
                onSignal(number)
            }
            source.resume()
            sources.append(source)
        }
    }

    /// The first signal that arrived, if any.
    var fired: Int32? {
        lock.lock(); defer { lock.unlock() }
        return firedSignal
    }

    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        lock.unlock()
        for source in sources { source.cancel() }
        for entry in previous {
            var action = entry.action
            sigaction(entry.signal, &action, nil)
        }
    }

    deinit { stop() }
}
#endif

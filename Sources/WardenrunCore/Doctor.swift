/// One line of `wardenrun doctor`: what was checked, how it came out, and why, in words that
/// never contain a secret or an environment value.
public struct CheckResult: Equatable, Sendable {
    public enum Status: String, Sendable {
        case ok, warn, fail, info
    }

    public let name: String
    public let status: Status
    public let detail: String

    public init(name: String, status: Status, detail: String) {
        self.name = name
        self.status = status
        self.detail = detail
    }
}

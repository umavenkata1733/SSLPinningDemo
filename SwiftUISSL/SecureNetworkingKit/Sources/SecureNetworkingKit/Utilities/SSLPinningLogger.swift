import Foundation

public final class SSLPinningLogger: @unchecked Sendable {
    public static let shared = SSLPinningLogger()

    private let prefix: String
    private let isEnabled: Bool

    public init(prefix: String = "SSL Pinning", isEnabled: Bool = SSLPinningLogger.defaultEnabled) {
        self.prefix = prefix
        self.isEnabled = isEnabled
    }

    public func log(_ message: String) {
        guard isEnabled else {
            return
        }

        print("[\(prefix)] \(message)")
    }

    public static var defaultEnabled: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }
}

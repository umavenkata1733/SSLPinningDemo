import Foundation

public enum PinningType: String, CaseIterable, Identifiable, Sendable {
    case certificate
    case publicKey

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .certificate:
            return "Certificate Pinning"
        case .publicKey:
            return "Public Key Pinning"
        }
    }
}

import Foundation
import Security

public protocol ClientIdentityProviding: Sendable {
    func clientIdentity(for host: String) -> SecIdentity?
}

public final class KeychainClientIdentityProvider: ClientIdentityProviding, @unchecked Sendable {
    private let label: String
    private let accessGroup: String?

    public init(label: String, accessGroup: String? = nil) {
        self.label = label
        self.accessGroup = accessGroup
    }

    public func clientIdentity(for host: String) -> SecIdentity? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true
        ]

        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            return nil
        }

        return item as! SecIdentity?
    }
}

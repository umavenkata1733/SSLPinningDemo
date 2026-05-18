import Foundation

public struct SSLPinningConfiguration: Sendable {
    public let pinnedHosts: [String: PinnedHostConfiguration]
    public let timeoutIntervalForRequest: TimeInterval
    public let timeoutIntervalForResource: TimeInterval
    public let clientIdentityProvider: ClientIdentityProviding?

    public init(
        pinnedHosts: [String: PinnedHostConfiguration],
        timeoutIntervalForRequest: TimeInterval = 30,
        timeoutIntervalForResource: TimeInterval = 60,
        clientIdentityProvider: ClientIdentityProviding? = nil
    ) {
        self.pinnedHosts = pinnedHosts
        self.timeoutIntervalForRequest = timeoutIntervalForRequest
        self.timeoutIntervalForResource = timeoutIntervalForResource
        self.clientIdentityProvider = clientIdentityProvider
    }

    public init(
        pinnedHost: String,
        certificateResourceName: String,
        expectedPublicKeyHash: String,
        timeoutIntervalForRequest: TimeInterval = 30,
        timeoutIntervalForResource: TimeInterval = 60,
        clientIdentityProvider: ClientIdentityProviding? = nil
    ) {
        self.init(
            pinnedHosts: [
                pinnedHost: PinnedHostConfiguration(
                    certificateResourceNames: [certificateResourceName],
                    publicKeyHashes: [expectedPublicKeyHash]
                )
            ],
            timeoutIntervalForRequest: timeoutIntervalForRequest,
            timeoutIntervalForResource: timeoutIntervalForResource,
            clientIdentityProvider: clientIdentityProvider
        )
    }

    public func policy(for host: String) -> PinnedHostConfiguration? {
        pinnedHosts[host]
    }

    public static let ups = SSLPinningConfiguration(
        pinnedHosts: [
            "developer.ups.com": PinnedHostConfiguration(
                certificateResourceNames: ["shups-ssl"],
                publicKeyHashes: ["fMeyaaDnNPentqoxyHdTq+oEsB/DFjtWGKzhgCwPF1g="]
            )
        ]
    )
}

public struct PinnedHostConfiguration: Sendable {
    public let certificateResourceNames: Set<String>
    public let publicKeyHashes: Set<String>

    public init(
        certificateResourceNames: Set<String> = [],
        publicKeyHashes: Set<String> = []
    ) {
        self.certificateResourceNames = certificateResourceNames
        self.publicKeyHashes = publicKeyHashes
    }

    public init(
        certificateResourceNames: [String],
        publicKeyHashes: [String]
    ) {
        self.init(
            certificateResourceNames: Set(certificateResourceNames),
            publicKeyHashes: Set(publicKeyHashes)
        )
    }
}

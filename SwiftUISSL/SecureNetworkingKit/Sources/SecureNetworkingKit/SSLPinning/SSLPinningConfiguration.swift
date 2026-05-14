import Foundation

public struct SSLPinningConfiguration: Sendable {
    public let pinnedHosts: [String: PinnedHostConfiguration]
    public let timeoutIntervalForRequest: TimeInterval
    public let timeoutIntervalForResource: TimeInterval

    public init(
        pinnedHosts: [String: PinnedHostConfiguration],
        timeoutIntervalForRequest: TimeInterval = 30,
        timeoutIntervalForResource: TimeInterval = 60
    ) {
        self.pinnedHosts = pinnedHosts
        self.timeoutIntervalForRequest = timeoutIntervalForRequest
        self.timeoutIntervalForResource = timeoutIntervalForResource
    }

    public init(
        pinnedHost: String,
        certificateResourceName: String,
        expectedPublicKeyHash: String,
        timeoutIntervalForRequest: TimeInterval = 30,
        timeoutIntervalForResource: TimeInterval = 60
    ) {
        self.init(
            pinnedHosts: [
                pinnedHost: PinnedHostConfiguration(
                    certificateResourceNames: [certificateResourceName],
                    publicKeyHashes: [expectedPublicKeyHash]
                )
            ],
            timeoutIntervalForRequest: timeoutIntervalForRequest,
            timeoutIntervalForResource: timeoutIntervalForResource
        )
    }

    public func policy(for host: String) -> PinnedHostConfiguration? {
        pinnedHosts[host]
    }

    public static let badSSL = SSLPinningConfiguration(
        pinnedHosts: [
            "sha256.badssl.com": PinnedHostConfiguration(
                certificateResourceNames: ["sha256-badssl"],
                publicKeyHashes: ["chBKGC2E4cdpgMD2jlsFLLJvoujxm9EUKcSlUiZN6Rc="]
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

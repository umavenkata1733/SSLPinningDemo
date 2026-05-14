import XCTest
@testable import SecureNetworkingKit

final class SSLPinningConfigurationTests: XCTestCase {
    func testSingleHostInitializerCreatesPinnedHostPolicy() {
        let configuration = SSLPinningConfiguration(
            pinnedHost: "api.example.com",
            certificateResourceName: "api-example",
            expectedPublicKeyHash: "base64-hash"
        )

        let policy = configuration.policy(for: "api.example.com")

        XCTAssertEqual(policy?.certificateResourceNames, ["api-example"])
        XCTAssertEqual(policy?.publicKeyHashes, ["base64-hash"])
        XCTAssertNil(configuration.policy(for: "other.example.com"))
    }

    func testMultiplePinsAreStoredForRotation() {
        let configuration = SSLPinningConfiguration(
            pinnedHosts: [
                "api.example.com": PinnedHostConfiguration(
                    certificateResourceNames: ["current-cert", "next-cert"],
                    publicKeyHashes: ["current-key-hash", "backup-key-hash"]
                )
            ],
            timeoutIntervalForRequest: 10,
            timeoutIntervalForResource: 20
        )

        let policy = configuration.policy(for: "api.example.com")

        XCTAssertEqual(policy?.certificateResourceNames, ["current-cert", "next-cert"])
        XCTAssertEqual(policy?.publicKeyHashes, ["current-key-hash", "backup-key-hash"])
        XCTAssertEqual(configuration.timeoutIntervalForRequest, 10)
        XCTAssertEqual(configuration.timeoutIntervalForResource, 20)
    }
}

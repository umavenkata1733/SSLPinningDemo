import CryptoKit
import Foundation
import Security

public final class PublicKeyPinningValidator: @unchecked Sendable {
    private let configuration: SSLPinningConfiguration
    private let logger: SSLPinningLogger

    public init(configuration: SSLPinningConfiguration, logger: SSLPinningLogger = .shared) {
        self.configuration = configuration
        self.logger = logger
    }

    public func validate(serverTrust: SecTrust, hostPolicy: PinnedHostConfiguration) -> Bool {
        logger.log("Public key pinning started")

        guard !hostPolicy.publicKeyHashes.isEmpty else {
            logger.log("Pinning failed: no public key hashes configured")
            return false
        }

        let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]
        guard let serverCertificate = certificateChain?.first,
              let serverPublicKey = SecCertificateCopyKey(serverCertificate),
              let rawPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) as Data? else {
            logger.log("Pinning failed: unable to extract server public key")
            return false
        }

        logger.log("Server public key extracted")

        guard let publicKeyData = subjectPublicKeyInfoData(for: serverPublicKey, rawPublicKeyData: rawPublicKeyData) else {
            logger.log("Pinning failed: unsupported public key algorithm")
            return false
        }

        let publicKeyHash = SHA256.hash(data: publicKeyData)
        let actualHash = Data(publicKeyHash).base64EncodedString()

        logger.log("Public key hash generated")
        logger.log("Expected hash: \(hostPolicy.publicKeyHashes.sorted().joined(separator: ", "))")
        logger.log("Actual hash: \(actualHash)")

        if hostPolicy.publicKeyHashes.contains(actualHash) {
            logger.log("Pinning passed")
            return true
        } else {
            logger.log("Pinning failed")
            return false
        }
    }

    private func subjectPublicKeyInfoData(for key: SecKey, rawPublicKeyData: Data) -> Data? {
        let attributes = SecKeyCopyAttributes(key) as? [CFString: Any]
        let keyType = attributes?[kSecAttrKeyType] as? String
        let keySize = attributes?[kSecAttrKeySizeInBits] as? Int

        if keyType == (kSecAttrKeyTypeRSA as String), keySize == 2_048 {
            return rsa2048ASN1Header + rawPublicKeyData
        }

        if keyType == (kSecAttrKeyTypeRSA as String), keySize == 4_096 {
            return rsa4096ASN1Header + rawPublicKeyData
        }

        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String), keySize == 256 {
            return ecSecp256r1ASN1Header + rawPublicKeyData
        }

        return nil
    }

    private var rsa2048ASN1Header: Data {
        Data([
            0x30, 0x82, 0x01, 0x22,
            0x30, 0x0d,
            0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00,
            0x03, 0x82, 0x01, 0x0f,
            0x00
        ])
    }

    private var rsa4096ASN1Header: Data {
        Data([
            0x30, 0x82, 0x02, 0x22,
            0x30, 0x0d,
            0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00,
            0x03, 0x82, 0x02, 0x0f,
            0x00
        ])
    }

    private var ecSecp256r1ASN1Header: Data {
        Data([
            0x30, 0x59,
            0x30, 0x13,
            0x06, 0x07,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42,
            0x00
        ])
    }
}

import Foundation
import Security

public final class CertificatePinningValidator: @unchecked Sendable {
    private let configuration: SSLPinningConfiguration
    private let logger: SSLPinningLogger

    public init(configuration: SSLPinningConfiguration, logger: SSLPinningLogger = .shared) {
        self.configuration = configuration
        self.logger = logger
    }

    public func validate(serverTrust: SecTrust, hostPolicy: PinnedHostConfiguration) -> Bool {
        logger.log("Certificate pinning started")

        guard !hostPolicy.certificateResourceNames.isEmpty else {
            logger.log("Certificate match failed: no local certificates configured")
            return false
        }

        let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]
        guard let serverCertificate = certificateChain?.first else {
            logger.log("Certificate match failed: unable to read server certificate")
            return false
        }
        logger.log("Server certificate extracted")

        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data

        for certificateResourceName in hostPolicy.certificateResourceNames {
            guard let localCertificateURL = Bundle.module.url(
                forResource: certificateResourceName,
                withExtension: "cer"
            ) else {
                logger.log("Local certificate not found in Bundle.module: \(certificateResourceName).cer")
                continue
            }

            do {
                let localCertificateData = try Data(contentsOf: localCertificateURL)
                logger.log("Local certificate loaded: \(certificateResourceName).cer")

                if serverCertificateData == localCertificateData {
                    logger.log("Certificate match passed")
                    return true
                }
            } catch {
                logger.log("Unable to load local certificate data: \(certificateResourceName).cer, \(error.localizedDescription)")
            }
        }

        logger.log("Certificate match failed")
        return false
    }
}

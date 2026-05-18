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

        guard let serverCertificate = leafCertificate(from: serverTrust) else {
            logger.log("Certificate match failed: unable to read server certificate")
            return false
        }
        logger.log("Server certificate extracted")

        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data

        for certificateResourceName in hostPolicy.certificateResourceNames {
            guard let localCertificateURL = SecureNetworkingKitBundle.url(
                forResource: certificateResourceName,
                withExtension: "cer"
            ) else {
                logger.log("Local certificate not found in package resources: \(certificateResourceName).cer")
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

    private func leafCertificate(from serverTrust: SecTrust) -> SecCertificate? {
        #if os(macOS)
        let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]
        return certificateChain?.first
        #else
        if #available(iOS 15.0, *) {
            let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate]
            return certificateChain?.first
        } else {
            return SecTrustGetCertificateAtIndex(serverTrust, 0)
        }
        #endif
    }
}

private enum SecureNetworkingKitBundle {
    private static let resourceBundleNames = [
        "SecureNetworkingKit_SecureNetworkingKit",
        "SecureNetworkingKit"
    ]

    static func url(forResource name: String, withExtension fileExtension: String) -> URL? {
        for bundle in candidateBundles {
            if let resourceURL = bundle.url(forResource: name, withExtension: fileExtension) {
                return resourceURL
            }
        }

        for baseURL in candidateBaseURLs {
            let directResourceURL = baseURL.appendingPathComponent("\(name).\(fileExtension)")
            if FileManager.default.fileExists(atPath: directResourceURL.path) {
                return directResourceURL
            }

            let nestedResourceURL = baseURL
                .appendingPathComponent("Resources")
                .appendingPathComponent("\(name).\(fileExtension)")
            if FileManager.default.fileExists(atPath: nestedResourceURL.path) {
                return nestedResourceURL
            }
        }

        loggerMissingResourceBundle()
        return nil
    }

    private static var candidateBundles: [Bundle] {
        candidateBaseURLs.compactMap { baseURL in
            if baseURL.pathExtension == "bundle",
               let bundle = Bundle(url: baseURL) {
                return bundle
            }

            for resourceBundleName in resourceBundleNames {
                let bundleURL = baseURL.appendingPathComponent("\(resourceBundleName).bundle")
                if let bundle = Bundle(url: bundleURL) {
                    return bundle
                }
            }

            return nil
        }
    }

    private static var candidateBaseURLs: [URL] {
        var urls: [URL] = []

        #if DEBUG
        if let override = ProcessInfo.processInfo.environment["PACKAGE_RESOURCE_BUNDLE_PATH"]
            ?? ProcessInfo.processInfo.environment["PACKAGE_RESOURCE_BUNDLE_URL"] {
            urls.append(URL(fileURLWithPath: override))
        }
        #endif

        urls.append(contentsOf: [
            Bundle.main.resourceURL,
            Bundle(for: BundleToken.self).resourceURL,
            Bundle.main.bundleURL,
            Bundle(for: BundleToken.self).bundleURL
        ].compactMap { $0 })

        return urls
    }

    private static func loggerMissingResourceBundle() {
        SSLPinningLogger.shared.log("SecureNetworkingKit resource not found in package bundle. Checked SecureNetworkingKit_SecureNetworkingKit.bundle, SecureNetworkingKit.bundle, and direct app/package resources.")
    }
}

private final class BundleToken {}

import Foundation
import Security

public final class SSLPinningURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let configuration: SSLPinningConfiguration
    private let pinningType: PinningType
    private let certificateValidator: CertificatePinningValidator
    private let publicKeyValidator: PublicKeyPinningValidator
    private let logger: SSLPinningLogger

    public init(
        configuration: SSLPinningConfiguration,
        pinningType: PinningType,
        logger: SSLPinningLogger = .shared
    ) {
        self.configuration = configuration
        self.pinningType = pinningType
        self.logger = logger
        self.certificateValidator = CertificatePinningValidator(configuration: configuration, logger: logger)
        self.publicKeyValidator = PublicKeyPinningValidator(configuration: configuration, logger: logger)
        super.init()
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    private func handle(
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        logger.log("Authentication challenge received")
        let host = challenge.protectionSpace.host
        logger.log("Host name: \(host)")

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            logger.log("Request cancelled: unsupported authentication challenge")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let hostPolicy = configuration.policy(for: host) else {
            logger.log("Request cancelled: host is not configured for pinning")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard performDefaultSSLValidation(serverTrust: serverTrust, host: host) else {
            logger.log("Request cancelled")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let pinningPassed: Bool
        switch pinningType {
        case .certificate:
            pinningPassed = certificateValidator.validate(serverTrust: serverTrust, hostPolicy: hostPolicy)
        case .publicKey:
            pinningPassed = publicKeyValidator.validate(serverTrust: serverTrust, hostPolicy: hostPolicy)
        }

        if pinningPassed {
            logger.log("Request allowed")
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            logger.log("Request cancelled")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    private func performDefaultSSLValidation(serverTrust: SecTrust, host: String) -> Bool {
        logger.log("Default SSL validation started")
        let policy = SecPolicyCreateSSL(true, host as CFString)
        SecTrustSetPolicies(serverTrust, policy)

        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)

        if isValid {
            logger.log("Default SSL validation passed")
        } else {
            let message = error.map { CFErrorCopyDescription($0) as String? } ?? "Unknown trust evaluation error"
            logger.log("Default SSL validation failed: \(message ?? "Unknown trust evaluation error")")
        }

        return isValid
    }
}

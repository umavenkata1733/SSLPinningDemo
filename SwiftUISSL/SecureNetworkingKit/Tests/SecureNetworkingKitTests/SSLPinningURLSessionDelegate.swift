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

        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            handleServerTrustChallenge(
                challenge: challenge,
                host: host,
                completionHandler: completionHandler
            )

        case NSURLAuthenticationMethodClientCertificate:
            handleClientCertificateChallenge(
                host: host,
                completionHandler: completionHandler
            )

        default:
            logger.log("Request cancelled: unsupported authentication challenge")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    private func handleServerTrustChallenge(
        challenge: URLAuthenticationChallenge,
        host: String,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            logger.log("Request cancelled: missing server trust")
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

    private func handleClientCertificateChallenge(
        host: String,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        logger.log("Client certificate challenge received")

        guard configuration.policy(for: host) != nil else {
            logger.log("Request cancelled: host is not configured for client authentication")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let clientIdentityProvider = configuration.clientIdentityProvider else {
            logger.log("Request cancelled: no client identity provider configured")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let identity = clientIdentityProvider.clientIdentity(for: host) else {
            logger.log("Request cancelled: client identity not found")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        logger.log("Client identity loaded")
        completionHandler(
            .useCredential,
            URLCredential(identity: identity, certificates: nil, persistence: .forSession)
        )
    }

    private func performDefaultSSLValidation(serverTrust: SecTrust, host: String) -> Bool {
        logger.log("Default SSL validation started")
        guard let policyHost = sslPolicyHost(from: host) else {
            logger.log("Default SSL validation failed: invalid host name")
            return false
        }

        let policy = SecPolicyCreateSSL(true, policyHost)
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

    private func sslPolicyHost(from host: String) -> CFString? {
        let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedHost.isEmpty else {
            return nil
        }

        return normalizedHost.withCString { hostCString in
            CFStringCreateWithCString(
                kCFAllocatorDefault,
                hostCString,
                CFStringBuiltInEncodings.UTF8.rawValue
            )
        }
    }
}

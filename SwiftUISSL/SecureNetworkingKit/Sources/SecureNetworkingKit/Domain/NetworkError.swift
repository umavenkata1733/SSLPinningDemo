import Foundation

public enum NetworkError: LocalizedError, Equatable, Sendable {
    case invalidResponse
    case invalidURL
    case sslPinningFailed
    case certificateResourceNotFound(String)
    case certificateDataLoadFailed(String)
    case publicKeyExtractionFailed
    case unsupportedPublicKeyAlgorithm
    case httpStatusCode(Int)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "The server returned an invalid response."
        case .invalidURL:
            return "The API URL is invalid."
        case .sslPinningFailed:
            return "SSL pinning validation failed."
        case .certificateResourceNotFound(let name):
            return "Certificate resource not found: \(name)."
        case .certificateDataLoadFailed(let name):
            return "Unable to load certificate resource: \(name)."
        case .publicKeyExtractionFailed:
            return "Unable to extract the server public key."
        case .unsupportedPublicKeyAlgorithm:
            return "The server public key algorithm is unsupported by this demo."
        case .httpStatusCode(let statusCode):
            return "Unexpected HTTP status code: \(statusCode)."
        }
    }
}

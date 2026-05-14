import Foundation

public final class SecureAPIClient: APIClientProtocol, @unchecked Sendable {
    private let endpoint: URL
    private let configuration: SSLPinningConfiguration
    private let logger: SSLPinningLogger
    private let additionalHeaders: [String: String]

    public convenience init() {
        self.init(
            endpoint: URL(string: "https://sha256.badssl.com/")!,
            configuration: .badSSL,
            logger: .shared
        )
    }

    public init(
        endpoint: URL,
        configuration: SSLPinningConfiguration,
        logger: SSLPinningLogger = .shared,
        additionalHeaders: [String: String] = [:]
    ) {
        self.endpoint = endpoint
        self.configuration = configuration
        self.logger = logger
        self.additionalHeaders = additionalHeaders
    }

    public func callBadSSL(using pinningType: PinningType) async throws -> APIResponse {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        return try await send(request, using: pinningType)
    }

    public func send(_ request: URLRequest, using pinningType: PinningType) async throws -> APIResponse {
        guard let url = request.url else {
            throw NetworkError.invalidURL
        }

        logger.log("Request started")
        logger.log("URL: \(url.absoluteString)")
        logger.log("Pinning type: \(pinningType.displayName)")

        let sessionDelegate = SSLPinningURLSessionDelegate(
            configuration: configuration,
            pinningType: pinningType,
            logger: logger
        )

        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalCacheData
        sessionConfiguration.urlCache = nil
        sessionConfiguration.timeoutIntervalForRequest = configuration.timeoutIntervalForRequest
        sessionConfiguration.timeoutIntervalForResource = configuration.timeoutIntervalForResource
        sessionConfiguration.httpAdditionalHeaders = additionalHeaders

        let urlSession = URLSession(
            configuration: sessionConfiguration,
            delegate: sessionDelegate,
            delegateQueue: nil
        )
        defer {
            urlSession.finishTasksAndInvalidate()
        }

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponse
        }

        logger.log("HTTP status code: \(httpResponse.statusCode)")
        logger.log("Response size: \(data.count) bytes")

        guard (200...299).contains(httpResponse.statusCode) else {
            throw NetworkError.httpStatusCode(httpResponse.statusCode)
        }

        return APIResponse(
            statusCode: httpResponse.statusCode,
            body: String(decoding: data, as: UTF8.self),
            responseSize: data.count
        )
    }
}

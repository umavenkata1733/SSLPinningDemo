import Foundation

public protocol APIClientProtocol: Sendable {
    func send(_ request: URLRequest, using pinningType: PinningType) async throws -> APIResponse
    func callBadSSL(using pinningType: PinningType) async throws -> APIResponse
}

public struct APIResponse: Sendable {
    public let statusCode: Int
    public let body: String
    public let responseSize: Int

    public init(statusCode: Int, body: String, responseSize: Int) {
        self.statusCode = statusCode
        self.body = body
        self.responseSize = responseSize
    }
}

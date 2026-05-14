import Foundation
import SecureNetworkingKit

@MainActor
final class SSLPinningViewModel: ObservableObject {
    @Published var selectedPinningType: PinningType = .certificate
    @Published var isLoading = false
    @Published var resultTitle = "Ready"
    @Published var resultMessage = "Choose a pinning strategy and call the test API."

    private let apiClient: APIClientProtocol

    init(apiClient: APIClientProtocol = SecureAPIClient()) {
        self.apiClient = apiClient
    }

    func callAPI() {
        isLoading = true
        resultTitle = "Calling API..."
        resultMessage = "Running \(selectedPinningType.displayName) against sha256.badssl.com."

        Task {
            do {
                let response = try await apiClient.callBadSSL(using: selectedPinningType)
                resultTitle = "Success"
                resultMessage = "Status \(response.statusCode), \(response.responseSize) bytes received."
            } catch {
                resultTitle = "Failure"
                resultMessage = error.localizedDescription
            }

            isLoading = false
        }
    }
}

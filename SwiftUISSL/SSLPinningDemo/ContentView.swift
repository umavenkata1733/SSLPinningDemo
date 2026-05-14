import SecureNetworkingKit
import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = SSLPinningViewModel()

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 24) {
                Picker("Pinning Type", selection: $viewModel.selectedPinningType) {
                    ForEach(PinningType.allCases) { type in
                        Text(type.displayName).tag(type)
                    }
                }
                .pickerStyle(.segmented)

                Button {
                    viewModel.callAPI()
                } label: {
                    Text("Call API")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isLoading)

                VStack(alignment: .leading, spacing: 8) {
                    Text(viewModel.resultTitle)
                        .font(.title2)
                        .fontWeight(.bold)

                    Text(viewModel.resultMessage)
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 8))

                Spacer()
            }
            .padding()
            .navigationTitle("SSL Pinning Demo")
        }
    }
}

#Preview {
    ContentView()
}

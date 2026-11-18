import SwiftUI

@main
struct RelayApproverApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.setup == nil {
                SetupView()
            } else if model.approver == nil {
                VStack(spacing: 16) {
                    if model.busy != nil {
                        ProgressView(model.busy ?? "")
                    } else {
                        Text("Not connected").font(.headline)
                        Button("Try again") { Task { await model.connect() } }
                        Button("Start over", role: .destructive) { model.reset() }
                    }
                }
                .padding()
            } else {
                TabView {
                    InboxView().tabItem { Label("Requests", systemImage: "tray") }
                    StatusView().tabItem { Label("Status", systemImage: "checkmark.shield") }
                }
            }
        }
        .onOpenURL { url in
            // poh://setup?… from the Camera app (relayctl app-link's QR code).
            Task { await model.open(link: url.absoluteString) }
        }
        .overlay(alignment: .bottom) {
            if let busy = model.busy, model.approver != nil || model.setup == nil {
                Text(busy).padding(8).background(.thinMaterial, in: Capsule()).padding()
            }
        }
        .alert(
            "Something went wrong",
            isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })
        ) {
            Button("OK") { model.error = nil }
        } message: {
            Text(model.error ?? "")
        }
    }
}

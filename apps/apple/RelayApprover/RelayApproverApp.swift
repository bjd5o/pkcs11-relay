import SwiftUI

@main
struct RelayApproverApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(model)
        }
        #if os(macOS)
        // The Mac app lives in the menu bar too (spec: approver apps): the count of what is
        // waiting, and a way back to the window. It keeps polling with the window closed.
        MenuBarExtra {
            MenuBarContent().environmentObject(model)
        } label: {
            let n = model.inbox.requests.count + model.inbox.pairings.count
            Image(systemName: n > 0 ? "key.fill" : "key")
            if n > 0 { Text("\(n)") }
        }
        #endif
    }
}

#if os(macOS)
struct MenuBarContent: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let requests = model.inbox.requests.count
        let pairings = model.inbox.pairings.count
        if model.setup == nil {
            Text("Not set up")
        } else if model.approver == nil {
            Text("Not connected")
        } else if requests + pairings == 0 {
            Text("Nothing waiting")
        } else {
            if requests > 0 { Text("\(requests) request\(requests == 1 ? "" : "s") waiting") }
            if pairings > 0 { Text("\(pairings) new client\(pairings == 1 ? "" : "s")") }
        }
        Divider()
        Button("Open Relay Approver") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut("o")
        Button("Quit") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}
#endif

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

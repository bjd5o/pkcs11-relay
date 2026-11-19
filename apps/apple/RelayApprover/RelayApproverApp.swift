import SwiftUI

@main
struct RelayApproverApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase
    #if os(iOS)
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #elseif os(macOS)
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    #endif

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(model)
                .onReceive(NotificationCenter.default.publisher(for: Push.token)) { n in
                    if let hex = n.object as? String { model.setPushToken(hex) }
                }
                .onReceive(NotificationCenter.default.publisher(for: Push.opened)) { _ in
                    model.tab = .requests
                    model.refresh()
                }
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active { model.becameActive() }
                    // The admin key's unlock ends when the app leaves the foreground.
                    if phase == .background { model.lockAdmin() }
                }
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
                TabView(selection: $model.tab) {
                    InboxView().tabItem { Label("Requests", systemImage: "tray") }.tag(AppModel.Tab.requests)
                    ClientsView().tabItem { Label("Clients", systemImage: "person.2") }.tag(AppModel.Tab.clients)
                    StatusView().tabItem { Label("Status", systemImage: "checkmark.shield") }.tag(AppModel.Tab.status)
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

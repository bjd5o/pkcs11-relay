// The iPad sample app for RelayPKCS11.xcframework: one screen to import a client config, list
// the keys the provider offers, sign a message with one, verify the signature, and read the
// provider's log (which carries the pairing code). PKCS#11 calls are in PKCS11.swift.

import SwiftUI
import UniformTypeIdentifiers

@main
struct SampleSignerApp: App {
    var body: some Scene {
        WindowGroup { SignerView() }
    }
}

@MainActor
final class SignerModel: ObservableObject {
    @Published var status = "No configuration yet. Import a folder with provider.toml, signer.asc and relay-ca.pem."
    @Published var keys: [SigningKey] = []
    @Published var selected: SigningKey.ID?
    @Published var message = "a message to sign"
    @Published var result = ""
    @Published var verified: Bool?
    @Published var busy = false
    @Published var log = ""

    private let module = PKCS11Module()

    var pairingCode: String? { keys.isEmpty ? ProviderConfig.pairingCode(in: log) : nil }

    func launched() async {
        #if DEBUG
        // The simulator test (tests/sim-provider.sh) hands over a host folder instead of Files.
        if let dir = ProcessInfo.processInfo.environment["SAMPLE_SIGNER_IMPORT"] {
            await importFolder(URL(fileURLWithPath: dir, isDirectory: true))
            return
        }
        #endif
        if ProviderConfig.exists { await reload() }
    }

    func importFolder(_ url: URL) async {
        busy = true
        defer { busy = false }
        await module.stop()
        do {
            try ProviderConfig.importFolder(url)
        } catch {
            status = "Import failed: \(error)"
            return
        }
        await reload()
    }

    /// Restart the provider (it reads its config in C_Initialize) and list the keys.
    func reload() async {
        busy = true
        defer { busy = false }
        do {
            try await module.start()
            ProviderConfig.protectClientKey()
            await refresh()
        } catch {
            status = "\(error)"
        }
    }

    func refresh() async {
        do {
            keys = try await module.signingKeys()
            if !keys.contains(where: { $0.id == selected }) { selected = keys.first?.id }
            status = keys.isEmpty
                ? "No keys yet. If the log shows a pairing code, compare it in the approver app, approve, then refresh."
                : "\(keys.count) signing keys"
        } catch {
            status = "\(error)"
        }
        readLog()
    }

    func sign() async {
        guard let key = keys.first(where: { $0.id == selected }) else { return }
        busy = true
        defer { busy = false }
        verified = nil
        result = "Waiting for approval…"
        let data = Data(message.utf8)
        do {
            let r = try await module.sign(key, message: data)
            let ok = try Verifier.verify(key, r, message: data)
            verified = ok
            result = "\(r.mechanism), \(r.signature.count) bytes: " + (ok ? "signature verified" : "SIGNATURE DOES NOT VERIFY")
                + "\n" + r.signature.base64EncodedString()
        } catch {
            verified = false
            result = "\(error)"
        }
        readLog()
    }

    func readLog() {
        log = ProviderConfig.logTail()
    }
}

struct SignerView: View {
    @StateObject private var model = SignerModel()
    @State private var importing = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Configuration") {
                    Button("Import config folder…") { importing = true }
                        .accessibilityIdentifier("import-config")
                    Text(model.status).accessibilityIdentifier("status")
                    if let code = model.pairingCode {
                        // Two texts, not LabeledContent, which reads as one combined element.
                        VStack(alignment: .leading) {
                            Text("Pairing code").font(.caption).foregroundStyle(.secondary)
                            Text(code)
                                .font(.title3.monospaced())
                                .textSelection(.enabled)
                                .accessibilityIdentifier("pairing-code")
                        }
                    }
                    Button("Refresh keys") { Task { await model.refresh() } }
                        .accessibilityIdentifier("refresh")
                }
                Section("Keys") {
                    ForEach(model.keys) { key in
                        Button {
                            model.selected = key.id
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(key.label)
                                    Text("\(key.token) · \(SignScheme(key)?.rawValue ?? "unsupported")")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if model.selected == key.id { Image(systemName: "checkmark") }
                            }
                        }
                        .accessibilityIdentifier("key-\(key.id)")
                    }
                }
                Section("Sign") {
                    TextField("Message", text: $model.message, axis: .vertical)
                        .accessibilityIdentifier("message")
                    Button("Sign") { Task { await model.sign() } }
                        .disabled(model.busy || model.selected == nil)
                        .accessibilityIdentifier("sign")
                    if !model.result.isEmpty {
                        Text(model.result)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                            .foregroundStyle(model.verified == false ? .red : .primary)
                            .accessibilityIdentifier(model.verified == true ? "signature-verified" : "sign-result")
                    }
                }
                Section("Provider log") {
                    Text(model.log.isEmpty ? "(empty)" : model.log)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                        .accessibilityIdentifier("provider-log")
                }
            }
            .navigationTitle("Sample Signer")
            .overlay(alignment: .topTrailing) {
                if model.busy { ProgressView().padding() }
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.folder]) { r in
            if case let .success(url) = r { Task { await model.importFolder(url) } }
        }
        .task { await model.launched() }
        .task {
            // The log changes while a request waits for approval.
            while !Task.isCancelled {
                model.readLog()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
}

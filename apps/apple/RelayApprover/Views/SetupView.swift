import SwiftUI
import UniformTypeIdentifiers

/// Screen 1: import the setup file from `relayctl app-config`, check the signer fingerprint.
struct SetupView: View {
    @EnvironmentObject var model: AppModel
    @State private var importing = false
    @State private var candidate: SetupFile?
    @State private var fingerprint = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Import the setup file made by `relayctl app-config`. It holds only public settings: the relay, its certificate authority and the manifest signer's key.")
                    Text("To copy it over USB: in Finder, select this iPhone, open Files, and drag the file onto Relay Approver. It then appears under On My iPhone › Relay Approver.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button("Choose setup file…") { importing = true }
                }
                if let c = candidate {
                    Section("Check before you continue") {
                        LabeledContent("Relay", value: c.relay_url)
                        LabeledContent("Device id", value: c.device_id)
                        LabeledContent("Attestation", value: "\(c.attestation_window_secs / 86_400) days")
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Manifest signer fingerprint").font(.caption).foregroundStyle(.secondary)
                            Text(grouped(fingerprint)).font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        Text("Compare this with `gpg --fingerprint` on your signing key. Continue only if they match.")
                            .font(.footnote).foregroundStyle(.secondary)
                        Button("The fingerprint matches") { Task { await model.confirmSetup(c) } }
                    }
                }
            }
            .navigationTitle("Set up")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
                do {
                    let url = try result.get()
                    let ok = url.startAccessingSecurityScopedResource()
                    defer { if ok { url.stopAccessingSecurityScopedResource() } }
                    (candidate, fingerprint) = try model.readSetup(try Data(contentsOf: url))
                } catch {
                    model.error = "That is not a usable setup file: \(error.localizedDescription)"
                }
            }
        }
    }

    private func grouped(_ hex: String) -> String {
        stride(from: 0, to: hex.count, by: 4).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: min(4, hex.count - i))])
        }.joined(separator: " ")
    }
}

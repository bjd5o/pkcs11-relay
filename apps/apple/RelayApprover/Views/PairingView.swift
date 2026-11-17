import SwiftUI

/// Screen 4: a new client. Compare the code with the client's log, then choose its keys.
struct PairingView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let pairing: PairingInfo
    @State private var chosen: Set<String> = []

    var body: some View {
        Form {
            Section {
                Text(pairing.code)
                    .font(.system(.title2, design: .monospaced))
                    .textSelection(.enabled)
            } header: {
                Text("Pairing code")
            } footer: {
                Text("The client printed a code to its log (`docker logs`, or over SSH). Approve only if every word matches.")
            }
            Section("Client") {
                LabeledContent("Id", value: pairing.clientId)
                LabeledContent("Host (claimed)", value: pairing.host)
            }
            Section("Keys this client may use") {
                ForEach(model.approver?.manifestKeys() ?? [], id: \.fingerprint) { k in
                    Toggle(isOn: Binding(
                        get: { chosen.contains(k.fingerprint) },
                        set: { if $0 { chosen.insert(k.fingerprint) } else { chosen.remove(k.fingerprint) } }
                    )) {
                        VStack(alignment: .leading) {
                            Text(k.label)
                            Text("\(k.role) · \(k.algorithm) · \(k.token)").font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("key-\(k.label)")
                }
            }
        }
        .navigationTitle("New client")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Approve") {
                    Task {
                        await model.approvePairing(pairing, keys: Array(chosen))
                        dismiss()
                    }
                }
                .accessibilityIdentifier("approve-pairing")
                .disabled(chosen.isEmpty)
            }
        }
    }
}

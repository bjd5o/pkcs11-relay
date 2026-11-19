import SwiftUI

/// Screen 4: a new client. Compare the code with the client's log, choose its keys and grant
/// window, then the YubiKey's attest key signs the client's grant (PIN and tap).
struct PairingView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let pairing: PairingInfo
    @State private var chosen: Set<String> = []
    @State private var window: UInt64 = 0
    @State private var pin = ""
    @FocusState private var pinFocused: Bool

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
            Section {
                GrantWindowPicker(window: $window)
            } footer: {
                Text("Every approver accepts this client's requests for this long after each approval; an approval renews it at 75%. Unused for longer, the client lapses and its next request asks you to renew.")
            }
            Section {
                SecureField("YubiKey PIN", text: $pin)
                    .focused($pinFocused)
                    .accessibilityIdentifier("pairing-pin")
                    #if os(iOS)
                    .keyboardType(.numberPad)
                    #endif
                Button("Approve and tap YubiKey") {
                    let entered = pin
                    pin = ""
                    pinFocused = false
                    Task {
                        if await model.approvePairing(
                            pairing, keys: Array(chosen), windowSecs: window, pin: entered)
                        {
                            dismiss()
                        }
                    }
                }
                .accessibilityIdentifier("approve-pairing")
                .disabled(chosen.isEmpty || pin.count < 6 || model.status?.pinFailed == true)
            } footer: {
                Text("Your YubiKey signs this client's grant, so the other approvers can answer it too.")
            }
        }
        .navigationTitle("New client")
        .scrollDismissesKeyboard(.interactively)
    }
}

/// A grant window up to the manifest's maximum.
struct GrantWindowPicker: View {
    @EnvironmentObject var model: AppModel
    @Binding var window: UInt64

    private var max: UInt64 { model.status?.maxClientGrantWindowSecs ?? 30 * 86_400 }

    private var choices: [UInt64] {
        let common: [UInt64] = [3_600, 86_400, 7 * 86_400, 30 * 86_400, 90 * 86_400, 365 * 86_400]
        return common.filter { $0 < max } + [max]
    }

    var body: some View {
        Picker("Grant window", selection: $window) {
            ForEach(choices, id: \.self) { Text(duration($0)).tag($0) }
        }
        .accessibilityIdentifier("grant-window")
        .onAppear { if window == 0 || window > max { window = Swift.min(7 * 86_400, max) } }
    }
}

func duration(_ secs: UInt64) -> String {
    if secs % 86_400 == 0 { return "\(secs / 86_400) day\(secs == 86_400 ? "" : "s")" }
    if secs % 3_600 == 0 { return "\(secs / 3_600) hour\(secs == 3_600 ? "" : "s")" }
    return "\(secs / 60) minutes"
}

func date(_ secs: UInt64) -> String {
    Date(timeIntervalSince1970: TimeInterval(secs)).formatted(date: .abbreviated, time: .shortened)
}

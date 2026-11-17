import SwiftUI

/// Screens 2 and 5: enrollment and status (attestation, keys, paired clients).
struct StatusView: View {
    @EnvironmentObject var model: AppModel
    @State private var pin = ""
    @FocusState private var pinFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                if let s = model.status {
                    Section("Device") {
                        LabeledContent("Id", value: s.deviceId)
                        LabeledContent("Manifest", value: "version \(s.manifestVersion), until \(date(s.manifestValidUntil))")
                    }
                    Section("Attestation") {
                        if let a = s.attestation {
                            LabeledContent("Valid until", value: date(a.notAfter))
                                .accessibilityIdentifier("attestation-valid")
                            LabeledContent("Renews from", value: date(a.renewAt))
                            Text("Renewal happens during an approval, in the same tap.")
                                .font(.footnote).foregroundStyle(.secondary)
                        } else {
                            Text("Not enrolled: clients reject this device's answers.")
                                .foregroundStyle(.red)
                        }
                        // Step 1: a tap without PIN reads which keys the YubiKey holds.
                        Button(model.discovered == nil ? "1. Read YubiKey (tap)" : "Read YubiKey again (tap)") {
                            pinFocused = false
                            Task { await model.readYubiKey() }
                        }
                        .accessibilityIdentifier("read-yubikey")
                        if let found = model.discovered {
                            if model.attestKeyFound {
                                Text("Found \(found.count) manifest key(s), including the attest key.")
                            } else {
                                Text("This YubiKey holds no attest key from the manifest.")
                                    .foregroundStyle(.red)
                                Text(model.discoveryReport).font(.caption.monospaced())
                                    .textSelection(.enabled)
                            }
                            // Step 2: PIN, then a second tap to sign the enrollment.
                            SecureField("YubiKey PIN", text: $pin)
                                .focused($pinFocused)
                                .accessibilityIdentifier("pin")
                                #if os(iOS)
                                .keyboardType(.numberPad)
                                #endif
                            Button(s.attestation == nil ? "2. Enroll (tap again)" : "2. Enroll again (tap again)") {
                                let entered = pin
                                pin = ""
                                pinFocused = false
                                Task { await model.enroll(pin: entered) }
                            }
                            .accessibilityIdentifier("enroll")
                            .disabled(pin.count < 6 || s.pinFailed || !model.attestKeyFound)
                        }
                    }
                    if s.pinFailed {
                        Section {
                            Text("A PIN was rejected. No further attempt is made until you choose to retry; the YubiKey blocks after 3 wrong PINs.")
                            Button("I have the right PIN: allow one more try") { model.retryPin() }
                        }
                    }
                    Section("Keys on this YubiKey") {
                        if s.keys.isEmpty { Text("None found yet: enroll first.").foregroundStyle(.secondary) }
                        ForEach(s.keys, id: \.fingerprint) { k in
                            VStack(alignment: .leading) {
                                Text(k.label)
                                Text("\(k.role) · \(k.algorithm)").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    Section("Paired clients") {
                        if s.clients.isEmpty { Text("None").foregroundStyle(.secondary) }
                        ForEach(s.clients, id: \.clientId) { c in
                            Text("\(c.clientId): \(c.keys.count) key(s)")
                        }
                    }
                }
                Section {
                    Button("Start over", role: .destructive) { model.reset() }
                }
            }
            .navigationTitle("Status")
            .refreshable { model.refresh() }
            .scrollDismissesKeyboard(.interactively)
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { pinFocused = false }
                }
            }
        }
    }

    private func date(_ secs: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(secs)).formatted(date: .abbreviated, time: .shortened)
    }
}

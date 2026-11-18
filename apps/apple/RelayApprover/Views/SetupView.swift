import SwiftUI

/// Screen 1: set up from a signed link (`relayctl app-link`), scanned with the Camera app or
/// pasted. The link is checked in Rust before anything here is shown; the person then compares
/// the signer fingerprint and chooses the attestation window.
struct SetupView: View {
    @EnvironmentObject var model: AppModel
    @State private var pasted = ""

    var body: some View {
        NavigationStack {
            Group {
                if let p = model.preview {
                    ConfirmSetupView(preview: p)
                } else {
                    Form {
                        Section {
                            Text("On the computer that holds your manifest signing key, run `relayctl app-link`. It prints a QR code.")
                            Text("Scan the code with the Camera app and open it in Relay Approver. The link is signed and expires after a few minutes; this app checks it before using anything in it.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                        Section("Or paste the link") {
                            TextField("poh://setup?…", text: $pasted, axis: .vertical)
                                #if os(iOS)
                                .textInputAutocapitalization(.never)
                                #endif
                                .autocorrectionDisabled()
                                .font(.system(.footnote, design: .monospaced))
                                .accessibilityIdentifier("setup-link")
                            Button("Check link") {
                                let link = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
                                Task { await model.open(link: link) }
                            }
                            .disabled(!pasted.hasPrefix("poh://"))
                        }
                    }
                }
            }
            .navigationTitle("Set up")
        }
    }
}

/// What the checked link says, for the person to confirm.
struct ConfirmSetupView: View {
    @EnvironmentObject var model: AppModel
    let preview: SetupPreview
    @State private var window: UInt64 = 0

    private var choices: [UInt64] {
        let max = preview.maxAttestationWindowSecs
        // Short windows let a gate test renewal (due at 75%) without a long wait.
        let common: [UInt64] = [15 * 60, 30 * 60, 3_600, 86_400, 3 * 86_400, 7 * 86_400, 14 * 86_400, 30 * 86_400, 90 * 86_400]
        return (common.filter { $0 < max } + [max])
    }

    var body: some View {
        Form {
            Section("Relay") {
                LabeledContent("Address", value: preview.relayUrl)
                LabeledContent("This device", value: preview.deviceId)
                    .accessibilityIdentifier("setup-device")
            }
            Section {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Fingerprint").font(.caption).foregroundStyle(.secondary)
                    Text(grouped(preview.signerFingerprint))
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
                identity
            } header: {
                Text("Manifest signer")
            } footer: {
                Text("Compare the fingerprint with `gpg --fingerprint` on your signing key. Continue only if it matches.")
            }
            Section("This link") {
                LabeledContent("Issued", value: date(preview.issuedAt))
                LabeledContent("Expires", value: date(preview.expiresAt))
            }
            Section {
                Picker("Attestation window", selection: $window) {
                    ForEach(choices, id: \.self) { Text(duration($0)).tag($0) }
                }
                .accessibilityIdentifier("attestation-window")
                LabeledContent("YubiKey attestation", value: preview.requireHardwareAttestation ? "required" : "not required")
            } header: {
                Text("Device")
            } footer: {
                Text("Clients accept this device's answers for this long after each attestation; it renews during an approval at 75%. The manifest allows at most \(duration(preview.maxAttestationWindowSecs)).")
            }
            Section {
                Button("The fingerprint matches") {
                    Task { await model.confirmSetup(windowSecs: window) }
                }
                .accessibilityIdentifier("confirm-setup")
                Button("Cancel", role: .cancel) { model.cancelSetup() }
            }
        }
        .onAppear { if window == 0 { window = preview.maxAttestationWindowSecs } }
    }

    @ViewBuilder private var identity: some View {
        switch preview.identity {
        case .verified(let ids):
            VStack(alignment: .leading, spacing: 4) {
                ForEach(ids, id: \.self) { Text($0) }
                Text("Verified by keys.openpgp.org").font(.caption).foregroundStyle(.secondary)
            }
        case .noIdentity:
            warning("keys.openpgp.org has this key but no confirmed email address for it, so the identity could not be verified.")
        case .notFound:
            warning("This key is not on keys.openpgp.org, so the identity could not be verified. Its owner can upload it there and confirm an email address.")
        case .unreachable(let reason):
            warning("Could not reach keys.openpgp.org (\(reason)), so the identity could not be verified.")
        case .mismatch(let reason):
            Label("\(reason). Do not continue unless you are sure of the fingerprint.", systemImage: "xmark.octagon.fill")
                .foregroundStyle(.red)
        }
    }

    private func warning(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
    }

    private func grouped(_ hex: String) -> String {
        stride(from: 0, to: hex.count, by: 4).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: min(4, hex.count - i))])
        }.joined(separator: " ")
    }

    private func date(_ secs: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(secs)).formatted(date: .abbreviated, time: .shortened)
    }

    private func duration(_ secs: UInt64) -> String {
        if secs % 86_400 == 0 { return "\(secs / 86_400) day\(secs == 86_400 ? "" : "s")" }
        if secs % 3_600 == 0 { return "\(secs / 3_600) hour\(secs == 3_600 ? "" : "s")" }
        return "\(secs / 60) minutes"
    }
}

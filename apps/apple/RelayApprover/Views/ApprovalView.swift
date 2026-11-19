import SwiftUI

/// Screen 3: the request in full. What the app checked is shown apart from what the requester
/// merely claims. Approve: Face ID, then the PIN, then the tap.
struct ApprovalView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let request: RequestView
    @State private var pin = ""
    @FocusState private var pinFocused: Bool
    @State private var result: String?

    var body: some View {
        Form {
            if let n = request.notice {
                Section {
                    if n.firstOnDevice {
                        Label("First request from \(request.clientId) on this device.", systemImage: "person.badge.plus")
                            .accessibilityIdentifier("first-request-notice")
                        Text("Paired on \(n.approvedBy) on \(date(n.issuedAt)), keys: \(n.keyLabels.joined(separator: ", ")). Approving also accepts this client here.")
                    }
                    if let lapsed = n.lapsedSince {
                        Label("This client's access lapsed on \(date(lapsed)).", systemImage: "clock.badge.exclamationmark")
                            .accessibilityIdentifier("lapsed-notice")
                        Text("Approving renews it for \(duration(n.windowSecs)), with keys: \(n.keyLabels.joined(separator: ", ")).")
                    }
                } header: {
                    Text("About this client")
                } footer: {
                    Text("Denying changes nothing; the notice comes back with its next request.")
                }
            }
            Section("Checked by this app") {
                LabeledContent("Client", value: request.clientId)
                LabeledContent("Key", value: "\(request.keyLabel) (\(request.keyRole))")
                LabeledContent("Token", value: request.token)
                LabeledContent("Operation", value: request.operation)
                LabeledContent("Mechanism", value: request.mechanism)
                LabeledContent("Time left", value: "\(request.secondsLeft) s")
            }
            Section("Content") {
                LabeledContent("Length", value: "\(request.inputLen) bytes")
                VStack(alignment: .leading) {
                    Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(request.inputSha256).font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                VStack(alignment: .leading) {
                    Text(request.inputTruncated ? "Hex (first bytes)" : "Hex").font(.caption)
                        .foregroundStyle(.secondary)
                    Text(request.inputPreviewHex).font(.system(.caption, design: .monospaced))
                        .lineLimit(6)
                }
            }
            Section {
                LabeledContent("Host", value: request.claimedHost)
                LabeledContent("Purpose", value: request.claimedPurpose)
                LabeledContent("Consumer", value: request.claimedConsumer)
            } header: {
                Text("Claimed by the requester, not verified")
            } footer: {
                Text("Approve only what you just started yourself.")
            }
            Section("Approve") {
                SecureField("YubiKey PIN", text: $pin)
                    .focused($pinFocused)
                    .accessibilityIdentifier("pin")
                    .textContentType(.password)
                    #if os(iOS)
                    .keyboardType(.numberPad)
                    #endif
                Button("Approve and tap YubiKey") {
                    let entered = pin
                    pin = ""
                    pinFocused = false
                    Task {
                        if let o = await model.approve(request, pin: entered) {
                            var done = ["Approved"]
                            if o.renewed { done.append("attestation renewed") }
                            if o.grantRenewed { done.append("client's access renewed") }
                            result = o.approved
                                ? done.joined(separator: "; ")
                                : "Not done: \(o.cardError ?? "card error"). The client was told."
                            if o.approved { dismiss() }
                        }
                    }
                }
                .accessibilityIdentifier("approve")
                .disabled(pin.count < 6 || model.status?.pinFailed == true)
                if model.status?.pinFailed == true {
                    Text("The last PIN was rejected. Retry it from Status when you are sure.")
                        .foregroundStyle(.red)
                }
                Button("Deny", role: .destructive) {
                    Task { await model.deny(request); dismiss() }
                }
            }
            if let result { Text(result) }
        }
        .navigationTitle("Approve?")
        .scrollDismissesKeyboard(.interactively)
        .toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("Done") { pinFocused = false }
            }
        }
    }
}

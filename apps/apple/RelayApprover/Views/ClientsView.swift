import SwiftUI

/// The Clients and Approvers screens (docs/client-grants.md). Every grant, revocation and
/// attestation shown is verified on this device; host, last seen and push kind are the relay's
/// word and labelled so. Loading them and every change needs Face ID (the admin key, one unlock
/// per hour at most); each change also needs the YubiKey and its PIN.
struct ClientsView: View {
    @EnvironmentObject var model: AppModel
    enum Section_: Hashable { case clients, approvers }
    @State private var showing: Section_ = .clients

    var body: some View {
        NavigationStack {
            List {
                Picker("Show", selection: $showing) {
                    Text("Clients").tag(Section_.clients)
                    Text("Approvers").tag(Section_.approvers)
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                switch showing {
                case .clients: clients
                case .approvers: approvers
                }
            }
            .navigationTitle(showing == .clients ? "Clients" : "Approvers")
            .navigationDestination(for: String.self) { id in
                if let c = model.clients.first(where: { $0.clientId == id }) {
                    ClientDetailView(client: c)
                }
            }
            .toolbar {
                ToolbarItem {
                    Button("Load from relay") { Task { await model.syncClients() } }
                        .accessibilityIdentifier("sync-clients")
                }
            }
            .refreshable { await model.syncClients() }
            .onAppear { model.loadLocalClients() }
        }
    }

    @ViewBuilder private var clients: some View {
        if model.clients.isEmpty {
            Text("No clients yet. Load from the relay to see the clients other approvers paired.")
                .foregroundStyle(.secondary)
        }
        ForEach(model.clients, id: \.clientId) { c in
            NavigationLink(value: c.clientId) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(c.clientId).font(.headline)
                        Spacer()
                        Text(stateText(c.state)).font(.caption).foregroundStyle(stateColor(c.state))
                    }
                    Text(c.keyLabels.joined(separator: ", ")).font(.subheadline)
                    if !c.accepted {
                        Text("Not accepted here: accepted with its first approval on this device")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            .accessibilityIdentifier("client-\(c.clientId)")
        }
    }

    @ViewBuilder private var approvers: some View {
        if model.approvers.isEmpty {
            Text("Load from the relay to see every approver.").foregroundStyle(.secondary)
        }
        ForEach(model.approvers, id: \.deviceId) { a in
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(a.deviceId + (a.thisDevice ? " (this device)" : "")).font(.headline)
                    Spacer()
                    Text(attestationText(a.attestationState)).font(.caption)
                        .foregroundStyle(a.attestationState == "valid" ? .green : .orange)
                }
                Text(a.keyLabels.joined(separator: ", ")).font(.subheadline)
                if let until = a.attestationNotAfter {
                    Text("Attested until \(date(until))").font(.caption)
                }
                Text("Push: \(a.pushKind) · last seen \(a.lastSeen == 0 ? "never" : date(a.lastSeen)) (as the relay reports)")
                    .font(.caption).foregroundStyle(.secondary)
                Text(a.deviceKeyFingerprint).font(.caption2.monospaced()).foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .accessibilityIdentifier("approver-\(a.deviceId)")
        }
    }
}

/// One client: what its grant says, and the actions (each needs the YubiKey).
struct ClientDetailView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let client: ClientInfo
    @State private var chosen: Set<String> = []
    @State private var window: UInt64 = 0
    @State private var pin = ""
    @State private var confirmRevoke = false
    @FocusState private var pinFocused: Bool

    var body: some View {
        Form {
            Section("Client") {
                LabeledContent("Id", value: client.clientId)
                LabeledContent("Status", value: stateText(client.state))
                VStack(alignment: .leading) {
                    Text("Pairing words").font(.caption).foregroundStyle(.secondary)
                    Text(client.code).font(.system(.body, design: .monospaced))
                }
                Text(client.fingerprint).font(.caption2.monospaced()).textSelection(.enabled)
                if let host = client.host {
                    LabeledContent("Host (as the relay reports)", value: host)
                }
            }
            Section("Grant") {
                if let by = client.approvedBy, let at = client.issuedAt {
                    LabeledContent("Signed on", value: "\(by), \(date(at))")
                }
                if let w = client.windowSecs { LabeledContent("Window", value: duration(w)) }
                if let e = client.expiresAt { LabeledContent("Expires", value: date(e)) }
                if client.state == "no_grant" {
                    Text("Paired before grants: other approvers can't answer this client until you give it a grant with Change keys.")
                        .font(.footnote)
                }
            }
            Section("Keys") {
                ForEach(model.approver?.manifestKeys() ?? [], id: \.fingerprint) { k in
                    Toggle(k.label, isOn: Binding(
                        get: { chosen.contains(k.fingerprint) },
                        set: { if $0 { chosen.insert(k.fingerprint) } else { chosen.remove(k.fingerprint) } }
                    ))
                    .accessibilityIdentifier("client-key-\(k.label)")
                }
                GrantWindowPicker(window: $window)
            }
            Section {
                SecureField("YubiKey PIN", text: $pin)
                    .focused($pinFocused)
                    .accessibilityIdentifier("client-pin")
                    #if os(iOS)
                    .keyboardType(.numberPad)
                    #endif
                Button("Change keys and tap YubiKey") {
                    act { await model.changeClient(client, keys: Array(chosen), windowSecs: window, pin: $0) }
                }
                .disabled(!ready || chosen.isEmpty)
                Button("Renew and tap YubiKey") {
                    act { await model.renewClient(client, pin: $0) }
                }
                .disabled(!ready || client.state == "no_grant")
                Button("Revoke", role: .destructive) { confirmRevoke = true }
                    .disabled(!ready)
            } footer: {
                Text("Your YubiKey signs each change; every approver follows it. Revoking takes effect here at once and reaches the other approvers through the relay.")
            }
        }
        .navigationTitle(client.clientId)
        .onAppear {
            chosen = Set(client.keyFingerprints)
            if let w = client.windowSecs { window = w }
        }
        .confirmationDialog("Revoke \(client.clientId)?", isPresented: $confirmRevoke, titleVisibility: .visible) {
            Button("Revoke and tap YubiKey", role: .destructive) {
                act { await model.revokeClient(client, pin: $0) }
            }
        } message: {
            Text("Every approver will refuse it. To use it again, the client has to be paired with a new key.")
        }
    }

    private var ready: Bool { pin.count >= 6 && model.status?.pinFailed != true }

    private func act(_ f: @escaping (String) async -> Bool) {
        let entered = pin
        pin = ""
        pinFocused = false
        Task { if await f(entered) { dismiss() } }
    }
}

func stateText(_ s: String) -> String {
    switch s {
    case "valid": return "Valid"
    case "renews_soon": return "Renews soon"
    case "lapsed": return "Lapsed (renews at its next approval)"
    case "cannot_verify": return "Can't verify (its attest key left the manifest)"
    case "revoked_in_manifest": return "Revoked in the manifest"
    case "no_grant": return "No grant: renew to share with other approvers"
    default: return s
    }
}

func stateColor(_ s: String) -> Color {
    switch s {
    case "valid": return .green
    case "renews_soon", "lapsed", "no_grant": return .orange
    default: return .red
    }
}

func attestationText(_ s: String) -> String {
    switch s {
    case "valid": return "Valid"
    case "renews_soon": return "Renews soon"
    case "expired": return "Expired"
    case "not_vouched": return "Not vouched for by the manifest"
    case "revoked_in_manifest": return "Revoked in the manifest"
    default: return s
    }
}

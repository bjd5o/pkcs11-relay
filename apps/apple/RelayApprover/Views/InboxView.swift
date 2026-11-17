import SwiftUI

/// Pending requests and pairings, refreshed by the long-poll while the app is open.
struct InboxView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationStack {
            List {
                if model.inbox.requests.isEmpty && model.inbox.pairings.isEmpty {
                    Text("Nothing waiting. Requests appear here while the app is open.")
                        .foregroundStyle(.secondary)
                }
                if !model.inbox.requests.isEmpty {
                    Section("Requests") {
                        ForEach(model.inbox.requests, id: \.requestId) { r in
                            NavigationLink(value: r.requestId) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(r.operation) with \(r.keyLabel)").font(.headline)
                                    Text("\(r.clientId) · claims: \(r.claimedPurpose)")
                                        .font(.subheadline).foregroundStyle(.secondary)
                                    Text("\(r.secondsLeft) s left").font(.caption)
                                }
                            }
                        }
                    }
                }
                if !model.inbox.pairings.isEmpty {
                    Section("New clients") {
                        ForEach(model.inbox.pairings, id: \.clientId) { p in
                            NavigationLink(value: "pair:" + p.clientId) {
                                VStack(alignment: .leading) {
                                    Text(p.clientId).font(.headline)
                                    Text(p.host).font(.subheadline).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                if model.inbox.rejected > 0 {
                    Section {
                        Button("Deny \(model.inbox.rejected) request(s) that failed their checks") {
                            Task { await model.answerRejections() }
                        }
                    }
                }
            }
            .navigationTitle("Requests")
            .navigationDestination(for: String.self) { id in
                if id.hasPrefix("pair:"), let p = model.inbox.pairings.first(where: { "pair:" + $0.clientId == id }) {
                    PairingView(pairing: p)
                } else if let r = model.inbox.requests.first(where: { $0.requestId == id }) {
                    ApprovalView(request: r)
                } else {
                    Text("This item is no longer pending.")
                }
            }
        }
    }
}

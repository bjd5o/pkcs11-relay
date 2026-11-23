// One HTTPS request held open by the server, trusting only the long-poll test root: what the relay
// route would do from the extension. A plain TLS connection, because the real one is rustls, to
// which URLSession's App Transport Security rules don't apply.

import Foundation
import Network
import Security

enum LongPoll {
    static var rootFile: URL { Proto.container.appendingPathComponent("longpoll-root.der") }

    private static func fail(_ s: String) -> Error {
        NSError(domain: "ctk-proto", code: 3, userInfo: [NSLocalizedDescriptionKey: s])
    }

    /// Returns a one-line report, or throws with the state the connection was in.
    static func hold(host: String, port: UInt16, secs: Int, log: @escaping (String) -> Void) throws -> String {
        guard let der = try? Data(contentsOf: rootFile), let root = SecCertificateCreateWithData(nil, der as CFData) else {
            throw fail("no long-poll root in the shared folder: tap Copy long-poll root in CTKProto")
        }
        let queue = DispatchQueue(label: "ctk-proto.longpoll")
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trustRef, done in
            let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
            SecTrustSetAnchorCertificates(trust, [root] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var e: CFError?
            let ok = SecTrustEvaluateWithError(trust, &e)
            if !ok { log("trust refused: \(e.map { "\($0)" } ?? "?")") }
            done(ok)
        }, queue)
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                                using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
        let done = DispatchSemaphore(value: 0)
        var result: Result<String, Error>?
        var last = "not started"
        let t0 = Date()
        func at() -> String { String(format: "%.1f s", Date().timeIntervalSince(t0)) }
        // Only on `queue`.
        func finish(_ r: Result<String, Error>) { if result == nil { result = r; done.signal() } }
        var got = Data()
        func read() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { d, _, complete, err in
                if let d { got.append(d) }
                let text = String(decoding: got, as: UTF8.self)
                if text.contains("\r\n\r\nheld \(secs)\n") {
                    finish(.success("\(text.prefix(15).trimmingCharacters(in: .whitespacesAndNewlines)), held \(secs) s, answered at \(at())"))
                } else if complete || err != nil {
                    finish(.failure(fail("connection ended at \(at()) without the answer: \(err.map { "\($0)" } ?? "closed"), \(got.count) B")))
                } else {
                    read()
                }
            }
        }
        conn.stateUpdateHandler = { state in
            last = "\(state)"
            switch state {
            case .ready:
                log("connected at \(at()), holding \(secs) s")
                let req = "GET /hold?secs=\(secs) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
                conn.send(content: Data(req.utf8), completion: .contentProcessed { e in
                    if let e { finish(.failure(fail("send: \(e)"))) }
                })
                read()
            case .failed(let e): finish(.failure(fail("failed at \(at()): \(e)")))
            case .waiting(let e): log("waiting at \(at()): \(e)")
            default: break
            }
        }
        conn.start(queue: queue)
        let timedOut = done.wait(timeout: .now() + .seconds(secs + 20)) == .timedOut
        return try queue.sync {
            conn.cancel()
            if timedOut && result == nil { throw fail("no answer after \(at()), state \(last)") }
            return try result!.get()
        }
    }
}

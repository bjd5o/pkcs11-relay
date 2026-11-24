// Imports a client config folder (from Files) into the app's container, where the provider's
// default lookup finds it: ~/Library/Application Support/relay-pkcs11/provider.toml, with HOME
// the container. No environment variable is set.
//
// The folder holds provider.toml and the files it names: the manifest signer (signer.asc), the
// relay CA (relay-ca.pem) and, with hardware attestation, its roots file. Each of those is
// copied next to provider.toml and its path rewritten to the copy. The provider's own state
// (manifest cache, client key, log) moves into the container too. Normally the folder has no
// client key: the provider creates one on its first run, the app shows the pairing code, and a
// person compares it in an approver app. A key file in the folder (moving an existing identity)
// is copied; an existing key in the container is kept when re-importing without one.

import Foundation

enum ProviderConfig {
    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("relay-pkcs11", isDirectory: true)
    }

    static var configFile: URL { directory.appendingPathComponent("provider.toml") }
    static var clientKey: URL { directory.appendingPathComponent("client.pem") }
    static var logFile: URL { directory.appendingPathComponent("provider.log") }

    static var exists: Bool { FileManager.default.fileExists(atPath: configFile.path) }

    /// Keys whose value names a file that comes with the config.
    private static let copied: Set<String> = ["relay_ca_file", "manifest_signer", "roots_file"]

    static func importFolder(_ source: URL) throws {
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let fm = FileManager.default
        let text: String
        do {
            text = try String(contentsOf: source.appendingPathComponent("provider.toml"), encoding: .utf8)
        } catch {
            throw Failure(description: "the folder has no readable provider.toml")
        }

        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.protectionKey: FileProtectionType.complete])
        // A new config may name another relay or manifest: drop the old caches and log.
        try? fm.removeItem(at: directory.appendingPathComponent("state"))
        try? fm.removeItem(at: logFile)

        func copy(_ name: String) throws -> URL {
            let from = source.appendingPathComponent(name)
            let to = directory.appendingPathComponent(name)
            guard fm.fileExists(atPath: from.path) else {
                throw Failure(description: "provider.toml names \(name), which is not in the folder")
            }
            try? fm.removeItem(at: to)
            try fm.copyItem(at: from, to: to)
            protect(to)
            return to
        }

        var out: [String] = []
        var sawLogPath = false, sawLogLevel = false
        var inTable = false
        let topLevel = [
            "log_path = \(quoted(logFile.path))",
            "log_level = \"info\"",
        ]
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") && !inTable {
                // Top-level keys must come before the first table.
                inTable = true
                out += topLevel.filter { $0.hasPrefix("log_path") ? !sawLogPath : !sawLogLevel }
                sawLogPath = true; sawLogLevel = true
            }
            guard let (key, value) = assignment(trimmed) else {
                out.append(line)
                continue
            }
            let name = (value as NSString).lastPathComponent
            switch key {
            case _ where copied.contains(key):
                out.append("\(key) = \(quoted(try copy(name).path))")
            case "manifest_url" where value.hasPrefix("file://"):
                let manifest = try copy(name)
                _ = try copy(name + ".asc")
                out.append("\(key) = \(quoted(manifest.absoluteString))")
            case "manifest_cache":
                out.append("\(key) = \(quoted(directory.appendingPathComponent("state/manifest.json").path))")
            case "client_key":
                if fm.fileExists(atPath: source.appendingPathComponent(name).path) {
                    try? fm.removeItem(at: clientKey)
                    try fm.copyItem(at: source.appendingPathComponent(name), to: clientKey)
                    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: clientKey.path)
                    protect(clientKey)
                }
                out.append("\(key) = \(quoted(clientKey.path))")
            case "log_path":
                sawLogPath = true
                out.append(topLevel[0])
            case "log_level":
                // The pairing code is logged at warn and requests at info; show both.
                sawLogLevel = true
                out.append(topLevel[1])
            default:
                out.append(line)
            }
        }
        if !inTable {
            out += topLevel.filter { $0.hasPrefix("log_path") ? !sawLogPath : !sawLogLevel }
        }
        try out.joined(separator: "\n").write(to: configFile, atomically: true, encoding: .utf8)
        protect(configFile)
    }

    /// The client key gets complete file protection once the provider has created it.
    static func protectClientKey() {
        if FileManager.default.fileExists(atPath: clientKey.path) { protect(clientKey) }
    }

    /// The last lines of the provider's log.
    static func logTail(_ lines: Int = 40) -> String {
        guard let text = try? String(contentsOf: logFile, encoding: .utf8) else { return "" }
        return text.split(separator: "\n", omittingEmptySubsequences: true).suffix(lines).joined(separator: "\n")
    }

    /// The pairing code from the log, while the client is waiting to be paired.
    static func pairingCode(in log: String) -> String? {
        guard let r = log.range(of: #"Pairing code: [^.\s]+"#, options: .regularExpression) else { return nil }
        return String(log[r].dropFirst("Pairing code: ".count))
    }

    // `key = "value"` on one line (the only form the provider's config files use for paths).
    private static func assignment(_ line: String) -> (String, String)? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let key = line[..<eq].trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty, key.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }),
              value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") else { return nil }
        return (key, String(value.dropFirst().dropLast()))
    }

    private static func quoted(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    private static func protect(_ url: URL) {
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    }
}

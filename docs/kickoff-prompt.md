We're starting implementation of pkcs11-relay, an approval-gated PKCS#11 provider. The repo has only docs so far.

Read CLAUDE.md, then docs/spec.md and docs/milestones-1-4.md in full before doing anything. The goal of this session is milestones 1 to 4 of the MVP plan: the shared Rust core, the relay server in Docker, the Linux/macOS PKCS#11 provider with a headless test approver, and relayctl with a real YubiKey.

Work in this order:

1. Run `git init`, add a .gitignore, and set up the Cargo workspace and crate skeletons described in docs/milestones-1-4.md, with fmt/clippy/test passing. Commit.
2. Write docs/wire-format.md from the spec and the defaults table in docs/milestones-1-4.md. Stop and show it to me before writing any core code; I'll review the encodings.
3. Implement milestone 1, then run its gate. Update docs/progress.md, record any decisions in docs/decisions.md, and give me a short summary (what's done, gate result, open questions) before starting the next milestone. Repeat for milestones 2 and 3.
4. For milestone 4, build relayctl and the test approver's PC/SC mode, but don't touch a YubiKey until I tell you which serial number and slots to use.

Ground rules: treat docs/spec.md as the source of truth and ask me before changing it or departing from it; ask before adding dependencies beyond those named in the docs; keep all verification logic in relay-core; never log PINs, keys or results. Use a task list so I can follow along.

# Integration tests

- `deploy/compose.test.yml`: the milestone 2 gate in containers (relay, three test
  approvers, and `relay-test-approver gate` as the client). Milestone 3 adds the provider
  scripts here, run by the client container with `pkcs11-tool`.
- `crates/relay-test-approver/tests/e2e.rs`: the same gate in-process, for `cargo test`.

//! Headless approver for CI and hardware tests, plus the milestone 2 gate client and the
//! fixture generator. Every protocol check is `relay-core`'s.
#![forbid(unsafe_code)]

pub mod approver;
pub mod fixtures;
pub mod gate;
pub mod relay;
pub mod sim_client;

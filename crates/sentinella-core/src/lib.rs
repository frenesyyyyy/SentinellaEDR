//! # sentinella-core
//!
//! Userspace core library for the Sentinella runtime sensor.
//! Handles eBPF program loading, event processing, and MITRE ATT&CK mapping.

pub mod events;
pub mod loader;
pub mod mitre;

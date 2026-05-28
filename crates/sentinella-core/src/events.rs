//! # Event Processing
//!
//! Converts raw eBPF `ExecEvent` structs into clean, serializable frontend events
//! with MITRE ATT&CK annotations.

use chrono::Utc;
use serde::Serialize;
use sentinella_common::{bytes_to_str, ExecEvent};

use crate::mitre::MitreMapping;

/// Frontend-ready process execution event.
/// This is what gets serialized to JSON and emitted to the Tauri frontend.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessExecEvent {
    /// ISO 8601 formatted timestamp
    pub timestamp: String,
    /// Monotonic kernel timestamp in nanoseconds (for ordering)
    pub timestamp_ns: u64,
    /// Process ID
    pub pid: u32,
    /// Parent process ID (0 if unavailable)
    pub ppid: u32,
    /// User ID
    pub uid: u32,
    /// Process comm name
    pub comm: String,
    /// Executable filename/path
    pub filename: String,
    /// MITRE ATT&CK tactic
    pub mitre_tactic: String,
    /// MITRE ATT&CK technique ID and name
    pub mitre_technique: String,
}

impl ProcessExecEvent {
    /// Convert a raw eBPF ExecEvent into a frontend-ready ProcessExecEvent.
    pub fn from_exec_event(raw: &ExecEvent) -> Self {
        let comm = bytes_to_str(&raw.comm).to_string();
        let filename = bytes_to_str(&raw.filename).to_string();

        // Map to MITRE ATT&CK
        let mapping = MitreMapping::classify(&comm, &filename);

        // Convert kernel monotonic ns to wall clock time
        // Note: bpf_ktime_get_ns is monotonic, not wall clock.
        // For Phase 1 we use current wall time as approximation.
        // Phase 2 will correlate monotonic with boot time for accuracy.
        let timestamp = Utc::now();

        ProcessExecEvent {
            timestamp: timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            timestamp_ns: raw.timestamp_ns,
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            comm,
            filename,
            mitre_tactic: mapping.tactic.to_string(),
            mitre_technique: mapping.technique.to_string(),
        }
    }
}

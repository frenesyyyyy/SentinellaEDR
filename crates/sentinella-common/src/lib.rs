//! # sentinella-common
//!
//! Shared data types between the eBPF kernel probe and the Rust userspace loader.
//! This crate is `no_std` compatible so it can be used in the eBPF program.
//!
//! The event struct uses `#[repr(C)]` with fixed-size byte arrays to ensure
//! safe sharing across the kernel/userspace boundary via BPF ring buffer.

#![no_std]

/// Maximum length for process comm name (matches kernel's TASK_COMM_LEN).
pub const COMM_LEN: usize = 16;

/// Maximum length for the filename/path captured from execve.
/// 256 bytes is a reasonable bound for Phase 1 — full PATH_MAX (4096) would
/// bloat ring buffer entries.
pub const FILENAME_LEN: usize = 256;

/// Event types for telemetry classification.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    /// Process execution via execve family
    ProcessExec = 1,
    /// Fileless execution via memfd_create
    FilelessExec = 2,
    /// Network connection attempt via connect
    NetworkConnect = 3,
}

/// Fixed-size event struct shared between eBPF and userspace.
///
/// # Layout
/// - `#[repr(C)]` ensures deterministic field ordering for cross-boundary sharing.
/// - All fields are fixed-size primitives or byte arrays — no pointers, no heap.
/// - Total size is predictable for the BPF verifier and ring buffer allocation.
///
/// # Fields
/// - `event_type`: Discriminant for the event kind (see [`EventType`]).
/// - `pid`: Process ID (actually the thread group leader's PID / tgid).
/// - `ppid`: Parent process ID (best-effort, may be 0 if unavailable).
/// - `uid`: Real user ID of the calling process.
/// - `timestamp_ns`: Kernel monotonic timestamp in nanoseconds (`bpf_ktime_get_ns`).
/// - `comm`: Process comm name, null-padded, from `bpf_get_current_comm`.
/// - `filename`: First argument to execve (the program path), null-padded.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub event_type: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
}

/// Zero-initialized default for use in eBPF context where we build the event
/// field by field before submitting to the ring buffer.
impl ExecEvent {
    pub const fn zeroed() -> Self {
        ExecEvent {
            event_type: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            timestamp_ns: 0,
            comm: [0u8; COMM_LEN],
            filename: [0u8; FILENAME_LEN],
        }
    }
}

/// Fixed-size network event struct shared between eBPF and userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub event_type: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub dest_ip: u32,
    pub dest_port: u16,
    pub _pad: u16,
}

impl NetworkEvent {
    pub const fn zeroed() -> Self {
        NetworkEvent {
            event_type: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            timestamp_ns: 0,
            comm: [0u8; COMM_LEN],
            dest_ip: 0,
            dest_port: 0,
            _pad: 0,
        }
    }
}

#[cfg(feature = "user")]
mod user_impls {
    use super::*;

    /// Helper to convert a null-terminated byte array to a UTF-8 string slice.
    /// Returns the string up to the first null byte, or the entire array if no null found.
    pub fn bytes_to_str(bytes: &[u8]) -> &str {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        core::str::from_utf8(&bytes[..len]).unwrap_or("<invalid-utf8>")
    }

    impl core::fmt::Debug for ExecEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ExecEvent")
                .field("event_type", &self.event_type)
                .field("pid", &self.pid)
                .field("ppid", &self.ppid)
                .field("uid", &self.uid)
                .field("timestamp_ns", &self.timestamp_ns)
                .field("comm", &bytes_to_str(&self.comm))
                .field("filename", &bytes_to_str(&self.filename))
                .finish()
        }
    }

    impl core::fmt::Debug for NetworkEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("NetworkEvent")
                .field("event_type", &self.event_type)
                .field("pid", &self.pid)
                .field("ppid", &self.ppid)
                .field("uid", &self.uid)
                .field("timestamp_ns", &self.timestamp_ns)
                .field("comm", &bytes_to_str(&self.comm))
                .field("dest_ip", &self.dest_ip)
                .field("dest_port", &self.dest_port)
                .finish()
        }
    }
}

#[cfg(feature = "user")]
pub use user_impls::bytes_to_str;

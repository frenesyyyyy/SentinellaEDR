//! # Sentinella eBPF Program
//!
//! Attaches to the `syscalls:sys_enter_execve` tracepoint and captures
//! process execution telemetry into a BPF ring buffer.
//!
//! ## Pipeline
//! 1. Fires on every `execve()` syscall entry
//! 2. Reads PID, UID, comm from kernel task_struct via BPF helpers
//! 3. Reads the filename pointer from the tracepoint context
//! 4. Packs a fixed-size `ExecEvent` and submits to ring buffer
//!
//! ## Limitations (Phase 1)
//! - No argv capture
//! - No blocking/enforcement
//! - PPID is 0 (requires task_struct traversal, deferred to Phase 2)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(no_mangle)]
#[link_section = "license"]
pub static _license: [u8; 4] = *b"GPL\0";

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes, bpf_probe_read_user,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use sentinella_common::{ExecEvent, EventType, NetworkEvent};

/// Ring buffer map for delivering events to userspace.
/// 256 KB — sufficient for bursty execve events.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Offset of the `filename` field in the sys_enter_execve tracepoint args.
/// Verify: cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
/// field:const char * filename; offset:16; size:8;
const FILENAME_OFFSET: usize = 16;

/// Tracepoint handler for `syscalls:sys_enter_execve`.
#[tracepoint]
pub fn sentinella_execve(ctx: TracePointContext) -> u32 {
    match try_sentinella_execve(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Silently succeed on error — never block execve
    }
}

/// Helper to detect restricted reverse shell tools
fn is_restricted(comm: &[u8; 16]) -> bool {
    (comm[0] == b'n' && comm[1] == b'c' && comm[2] == 0) || // "nc"
    (comm[0] == b'n' && comm[1] == b'c' && comm[2] == b'a' && comm[3] == b't' && comm[4] == 0) || // "ncat"
    (comm[0] == b's' && comm[1] == b'o' && comm[2] == b'c' && comm[3] == b'a' && comm[4] == b't' && comm[5] == 0) || // "socat"
    (comm[0] == b'n' && comm[1] == b'e' && comm[2] == b't' && comm[3] == b'c' && comm[4] == b'a' && comm[5] == b't' && comm[6] == 0) // "netcat"
}

/// Helper to detect if the executed binary path matches restricted tools
fn is_restricted_path(path: &[u8; 256]) -> bool {
    let mut len = 0;
    for i in 0..256 {
        if path[i] == 0 {
            break;
        }
        len += 1;
    }

    // Check "nc" (len >= 2)
    if len >= 2 {
        let idx = len - 2;
        if idx < 255 {
            if path[idx] == b'n' && path[idx + 1] == b'c' {
                if idx == 0 {
                    return true;
                } else if path[idx - 1] == b'/' {
                    return true;
                }
            }
        }
    }

    // Check "ncat" (len >= 4)
    if len >= 4 {
        let idx = len - 4;
        if idx < 253 {
            if path[idx] == b'n' && path[idx + 1] == b'c' && path[idx + 2] == b'a' && path[idx + 3] == b't' {
                if idx == 0 {
                    return true;
                } else if path[idx - 1] == b'/' {
                    return true;
                }
            }
        }
    }

    // Check "socat" (len >= 5)
    if len >= 5 {
        let idx = len - 5;
        if idx < 252 {
            if path[idx] == b's' && path[idx + 1] == b'o' && path[idx + 2] == b'c' && path[idx + 3] == b'a' && path[idx + 4] == b't' {
                if idx == 0 {
                    return true;
                } else if path[idx - 1] == b'/' {
                    return true;
                }
            }
        }
    }

    // Check "netcat" (len >= 6)
    if len >= 6 {
        let idx = len - 6;
        if idx < 251 {
            if path[idx] == b'n' && path[idx + 1] == b'e' && path[idx + 2] == b't' && path[idx + 3] == b'c' && path[idx + 4] == b'a' && path[idx + 5] == b't' {
                if idx == 0 {
                    return true;
                } else if path[idx - 1] == b'/' {
                    return true;
                }
            }
        }
    }

    false
}

/// Inner function with Result for ergonomic error handling.
fn try_sentinella_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    // --- Gather process metadata ---
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Get current comm (task name)
    let comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // Read the filename pointer from tracepoint context args
    let filename_ptr: *const u8 = unsafe {
        ctx.read_at(FILENAME_OFFSET)
            .map_err(|e| e as i64)?
    };

    // Read the filename string into a stack-allocated buffer.
    // This is required because BPF copy helpers (like bpf_probe_read_user_str)
    // are only permitted to write to the BPF stack, not directly to map memory.
    let mut filename = [0u8; sentinella_common::FILENAME_LEN];
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut filename,
        )
    };

    // ACTIVE ENFORCEMENT: Kill restricted reverse shell commands immediately using SIGKILL (9)
    if is_restricted(&comm) || is_restricted_path(&filename) {
        unsafe {
            let _ = aya_ebpf::helpers::bpf_send_signal(9);
        }
    }

    // --- Reserve ring buffer entry ---
    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0), // Ring buffer full — drop silently
    };

    let event = entry.as_mut_ptr();

    unsafe {
        // Fill fixed fields using volatile writes to ensure direct memory access
        core::ptr::write_volatile(&mut (*event).event_type, EventType::ProcessExec as u32);
        core::ptr::write_volatile(&mut (*event).pid, pid);
        core::ptr::write_volatile(&mut (*event).ppid, 0); // Phase 2: traverse task_struct->real_parent
        core::ptr::write_volatile(&mut (*event).uid, uid);
        core::ptr::write_volatile(&mut (*event).timestamp_ns, timestamp_ns);
        core::ptr::write_volatile(&mut (*event).comm, comm);

        // Copy filename from stack buffer to reserved ring buffer memory
        let filename_dest = &mut (*event).filename as *mut u8;
        for i in 0..sentinella_common::FILENAME_LEN {
            core::ptr::write_volatile(filename_dest.add(i), filename[i]);
        }
    }

    // Submit the entry — makes it visible to userspace consumer
    entry.submit(0);

    Ok(0)
}

/// Tracepoint handler for `syscalls:sys_enter_memfd_create`.
#[tracepoint]
pub fn sentinella_memfd_create(ctx: TracePointContext) -> u32 {
    match try_sentinella_memfd_create(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn is_benign_memfd_caller(comm: &[u8; 16]) -> bool {
    // 1. "pulseaudio" (10 chars): p-u-l-s-e-a-u-d-i-o
    if comm[0] == b'p' && comm[1] == b'u' && comm[2] == b'l' && comm[3] == b's' && comm[4] == b'e' && comm[5] == b'a' && comm[6] == b'u' && comm[7] == b'd' && comm[8] == b'i' && comm[9] == b'o' {
        return true;
    }
    // 2. "pipewire" (8 chars): p-i-p-e-w-i-r-e
    if comm[0] == b'p' && comm[1] == b'i' && comm[2] == b'p' && comm[3] == b'e' && comm[4] == b'w' && comm[5] == b'i' && comm[6] == b'r' && comm[7] == b'e' {
        return true;
    }
    // 3. "chrome" (6 chars): c-h-r-o-m-e
    if comm[0] == b'c' && comm[1] == b'h' && comm[2] == b'r' && comm[3] == b'o' && comm[4] == b'm' && comm[5] == b'e' {
        return true;
    }
    // 4. "chromium" (8 chars): c-h-r-o-m-i-u-m
    if comm[0] == b'c' && comm[1] == b'h' && comm[2] == b'r' && comm[3] == b'o' && comm[4] == b'm' && comm[5] == b'i' && comm[6] == b'u' && comm[7] == b'm' {
        return true;
    }
    // 5. "firefox" (7 chars): f-i-r-e-f-o-x
    if comm[0] == b'f' && comm[1] == b'i' && comm[2] == b'r' && comm[3] == b'e' && comm[4] == b'f' && comm[5] == b'o' && comm[6] == b'x' {
        return true;
    }
    // 6. "gnome-shell" (11 chars): g-n-o-m-e---s-h-e-l-l
    if comm[0] == b'g' && comm[1] == b'n' && comm[2] == b'o' && comm[3] == b'm' && comm[4] == b'e' && comm[5] == b'-' && comm[6] == b's' && comm[7] == b'h' && comm[8] == b'e' && comm[9] == b'l' && comm[10] == b'l' {
        return true;
    }
    // 7. "Xorg" (4 chars): X-o-r-g
    if comm[0] == b'X' && comm[1] == b'o' && comm[2] == b'r' && comm[3] == b'g' && comm[4] == 0 {
        return true;
    }
    // 8. "dbus-daemon" (11 chars): d-b-u-s---d-a-e-m-o-n
    if comm[0] == b'd' && comm[1] == b'b' && comm[2] == b'u' && comm[3] == b's' && comm[4] == b'-' && comm[5] == b'd' && comm[6] == b'a' && comm[7] == b'e' && comm[8] == b'm' && comm[9] == b'o' && comm[10] == b'n' {
        return true;
    }
    // 9. "systemd" (7 chars): s-y-s-t-e-m-d
    if comm[0] == b's' && comm[1] == b'y' && comm[2] == b's' && comm[3] == b't' && comm[4] == b'e' && comm[5] == b'm' && comm[6] == b'd' {
        return true;
    }

    false
}

fn try_sentinella_memfd_create(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // Filter out memfd_create calls from standard benign desktop processes
    if is_benign_memfd_caller(&comm) {
        return Ok(0);
    }

    // Read the name pointer from tracepoint context args (offset 16)
    let name_ptr: *const u8 = unsafe {
        ctx.read_at(16)
            .map_err(|e| e as i64)?
    };

    let mut name = [0u8; sentinella_common::FILENAME_LEN];
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(
            name_ptr,
            &mut name,
        )
    };

    // --- Reserve ring buffer entry ---
    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();

    unsafe {
        core::ptr::write_volatile(&mut (*event).event_type, EventType::FilelessExec as u32);
        core::ptr::write_volatile(&mut (*event).pid, pid);
        core::ptr::write_volatile(&mut (*event).ppid, 0);
        core::ptr::write_volatile(&mut (*event).uid, uid);
        core::ptr::write_volatile(&mut (*event).timestamp_ns, timestamp_ns);
        core::ptr::write_volatile(&mut (*event).comm, comm);

        // Copy name from stack to event's filename field
        let filename_dest = &mut (*event).filename as *mut u8;
        for i in 0..sentinella_common::FILENAME_LEN {
            core::ptr::write_volatile(filename_dest.add(i), name[i]);
        }
    }

    entry.submit(0);

    Ok(0)
}

/// Tracepoint handler for `syscalls:sys_enter_connect`.
#[tracepoint]
pub fn sentinella_connect(ctx: TracePointContext) -> u32 {
    match try_sentinella_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// Minimal definition of sockaddr_in for IPv4 parsing
#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32, // in_addr structure holds a single u32
}

fn try_sentinella_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // Read the uservaddr pointer from tracepoint args at offset 24
    let uservaddr_ptr: *const sockaddr_in = unsafe {
        ctx.read_at(24)
            .map_err(|e| e as i64)?
    };

    if uservaddr_ptr.is_null() {
        return Ok(0);
    }

    // Safely copy the sockaddr_in structure from user space
    let sock_addr = unsafe {
        bpf_probe_read_user(uservaddr_ptr)
            .map_err(|e| e as i64)?
    };

    // We only inspect IPv4 (AF_INET = 2) connections
    if sock_addr.sin_family != 2 {
        return Ok(0);
    }

    // Convert IP and Port to host byte order
    let dest_ip = u32::from_be(sock_addr.sin_addr);
    let dest_port = u16::from_be(sock_addr.sin_port);

    // Reserve ring buffer entry
    let mut entry = match EVENTS.reserve::<NetworkEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = entry.as_mut_ptr();

    unsafe {
        core::ptr::write_volatile(&mut (*event).event_type, EventType::NetworkConnect as u32);
        core::ptr::write_volatile(&mut (*event).pid, pid);
        core::ptr::write_volatile(&mut (*event).ppid, 0);
        core::ptr::write_volatile(&mut (*event).uid, uid);
        core::ptr::write_volatile(&mut (*event).timestamp_ns, timestamp_ns);
        core::ptr::write_volatile(&mut (*event).comm, comm);
        core::ptr::write_volatile(&mut (*event).dest_ip, dest_ip);
        core::ptr::write_volatile(&mut (*event).dest_port, dest_port);
        core::ptr::write_volatile(&mut (*event)._pad, 0);
    }

    entry.submit(0);

    Ok(0)
}


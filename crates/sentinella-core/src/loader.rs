//! # eBPF Loader
//!
//! Loads the embedded eBPF object, attaches to the `syscalls:sys_enter_execve`
//! tracepoint, and reads events from the ring buffer.
//!
//! The loader is designed to be called from both:
//! - Tauri backend (via sentinella-tauri commands)
//! - Standalone daemon mode (future sentinella-agent)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{error, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use sentinella_common::ExecEvent;
use crate::events::ProcessExecEvent;

/// Sensor handle returned after starting the eBPF sensor.
pub struct SensorHandle {
    running: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl SensorHandle {
    /// Signal the sensor to stop and wait for the task to finish.
    pub async fn stop(&mut self) {
        info!("Stopping Sentinella sensor...");
        self.running.store(false, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        info!("Sentinella sensor stopped.");
    }

    /// Check if the sensor is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

/// Start the Sentinella eBPF sensor.
///
/// # Arguments
/// - `ebpf_bytes`: The compiled eBPF object bytecode
/// - `event_tx`: Channel sender for processed events
///
/// # Errors
/// - Missing BPF capabilities (needs root or CAP_BPF + CAP_PERFMON)
/// - Kernel too old (needs >= 5.8 for ring buffer)
/// - eBPF verifier rejection
pub async fn start_sensor(
    ebpf_bytes: &[u8],
    event_tx: mpsc::UnboundedSender<ProcessExecEvent>,
) -> Result<SensorHandle> {
    info!("Loading Sentinella eBPF program...");

    // Load the eBPF object
    let mut ebpf = Ebpf::load(ebpf_bytes).context(
        "Failed to load eBPF program. Ensure you have root privileges or \
         CAP_BPF + CAP_PERFMON capabilities, and kernel >= 5.8."
    )?;

    // Initialize aya-log (maps eBPF log messages to Rust log crate)
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger (non-fatal): {}", e);
    }

    // Get the tracepoint program and attach
    let program: &mut TracePoint = ebpf
        .program_mut("sentinella_execve")
        .context("eBPF program 'sentinella_execve' not found in object")?
        .try_into()
        .context("Program is not a TracePoint")?;

    program
        .load()
        .context("Failed to load tracepoint program into kernel")?;

    program
        .attach("syscalls", "sys_enter_execve")
        .context(
            "Failed to attach to tracepoint syscalls:sys_enter_execve. \
             Ensure the tracepoint exists: \
             cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format"
        )?;

    info!("eBPF tracepoint attached: syscalls:sys_enter_execve");

    // Get the ring buffer map
    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("Map 'EVENTS' not found in eBPF object")?
    ).context("Failed to create RingBuf from EVENTS map")?;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Spawn the event processing loop
    let task = tokio::task::spawn(async move {
        if let Err(e) = event_loop(ring_buf, event_tx, running_clone, ebpf).await {
            error!("Sensor event loop error: {}", e);
        }
    });

    Ok(SensorHandle {
        running,
        task: Some(task),
    })
}

/// Async event loop that reads from the ring buffer.
///
/// Wraps the RingBuf in AsyncFd for epoll-based notification — no polling.
async fn event_loop(
    ring_buf: RingBuf<aya::maps::MapData>,
    event_tx: mpsc::UnboundedSender<ProcessExecEvent>,
    running: Arc<AtomicBool>,
    _ebpf: Ebpf, // Keep alive — dropping detaches programs
) -> Result<()> {
    // Wrap the RingBuf in AsyncFd for async I/O
    let mut async_fd = AsyncFd::new(ring_buf)
        .context("Failed to create AsyncFd for ring buffer")?;

    info!("Sentinella event loop started. Waiting for execve events...");

    while running.load(Ordering::Relaxed) {
        // Wait for the ring buffer fd to become readable
        let mut guard = async_fd.readable_mut().await
            .context("Error waiting for ring buffer readability")?;

        // Drain all available events from the ring buffer
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            let data = item.as_ref();

            if data.len() < std::mem::size_of::<ExecEvent>() {
                warn!(
                    "Undersized event: {} bytes (expected {})",
                    data.len(),
                    std::mem::size_of::<ExecEvent>()
                );
                continue;
            }

            // Safety: ExecEvent is #[repr(C)] with fixed-size fields,
            // and we verified the buffer is large enough.
            let raw_event: ExecEvent = unsafe {
                std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent)
            };

            let processed = ProcessExecEvent::from_exec_event(&raw_event);

            if event_tx.send(processed).is_err() {
                info!("Event receiver dropped, stopping event loop");
                return Ok(());
            }
        }

        // Clear readiness so we wait for the next kernel notification
        guard.clear_ready();
    }

    info!("Sentinella event loop stopped.");
    Ok(())
}

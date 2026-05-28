//! # Sentinella Desktop — Main Entry Point
//!
//! Launches the Tauri v2 application with the Sentinella eBPF sensor backend.
//! Phase 8: Event Flood Aggregation — debounces benign execve events to protect the UI.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tauri::{AppHandle, Emitter, State};

/// Process event payload serializable to JSON.
#[derive(serde::Serialize, Clone, Debug)]
pub struct ProcessEvent {
    pub timestamp: String,
    pub pid: u32,
    pub process: String,
    pub event_type: String,
    pub details: String,
    pub enforcement: String,
    /// Number of aggregated duplicate events (None or 1 = single event)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 8 — Event Flood Aggregator
// Buffers benign (non-threat) events for a short time window and collapses
// duplicates by command name so the UI never receives an event flood from
// highly-threaded applications like Firefox or Chrome.
// ────────────────────────────────────────────────────────────────────────────
const AGGREGATION_WINDOW_MS: u64 = 250;

/// Key used to group duplicate events in the aggregation window.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AggKey {
    process: String,
    event_type: String,
}

/// Buffered state for a single aggregation key.
#[derive(Clone, Debug)]
struct AggBucket {
    /// The most recent event for this key (used as the representative).
    representative: ProcessEvent,
    /// How many raw events have been collapsed into this bucket.
    count: u32,
}

/// Thread-safe event aggregator shared between the ring-buffer reader and the
/// periodic flush task.
struct EventAggregator {
    buffer: Mutex<HashMap<AggKey, AggBucket>>,
}

impl EventAggregator {
    fn new() -> Self {
        Self {
            buffer: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a benign event into the aggregation buffer.
    async fn insert(&self, event: ProcessEvent) {
        let key = AggKey {
            process: event.process.clone(),
            event_type: event.event_type.clone(),
        };
        let mut buf = self.buffer.lock().await;
        let entry = buf.entry(key).or_insert_with(|| AggBucket {
            representative: event.clone(),
            count: 0,
        });
        entry.count += 1;
        // Always keep the latest timestamp/pid as the representative
        entry.representative = event;
    }

    /// Drain the buffer and return all aggregated events ready for emission.
    async fn flush(&self) -> Vec<ProcessEvent> {
        let mut buf = self.buffer.lock().await;
        let drained: Vec<ProcessEvent> = buf
            .drain()
            .map(|(_, bucket)| {
                let mut ev = bucket.representative;
                ev.count = if bucket.count > 1 {
                    Some(bucket.count)
                } else {
                    None
                };
                ev
            })
            .collect();
        drained
    }
}

fn is_restricted_comm(comm: &[u8; 16]) -> bool {
    let s = sentinella_common::bytes_to_str(comm);
    matches!(s, "nc" | "ncat" | "netcat" | "socat")
}

fn is_restricted_filename(filename: &[u8; 256]) -> bool {
    let s = sentinella_common::bytes_to_str(filename);
    s == "nc" || s.ends_with("/nc") ||
    s == "ncat" || s.ends_with("/ncat") ||
    s == "netcat" || s.ends_with("/netcat") ||
    s == "socat" || s.ends_with("/socat")
}

fn is_benign_memfd(comm: &str, name: &str) -> bool {
    let comm_lower = comm.to_lowercase();
    if comm_lower.contains("pulse")
        || comm_lower.contains("pipewire")
        || comm_lower.contains("chrome")
        || comm_lower.contains("chromium")
        || comm_lower.contains("firefox")
        || comm_lower.contains("gnome")
        || comm_lower.contains("wayland")
        || comm_lower.contains("xorg")
        || comm_lower.contains("dbus")
        || comm_lower.contains("systemd")
        || comm_lower.contains("glycin")
        || comm_lower.contains("gvfs")
        || comm_lower.contains("gdm")
        || comm_lower.contains("packagekit")
        || comm_lower.contains("sudo")
        || comm_lower.contains("bash")
        || comm_lower.contains("zsh")
        || comm_lower.contains("fish")
    {
        return true;
    }

    let name_lower = name.to_lowercase();
    if name_lower.is_empty()
        || name_lower.contains("pulse")
        || name_lower.contains("pipewire")
        || name_lower.contains("wayland")
        || name_lower.contains("mesa")
        || name_lower.contains("glycin")
        || name_lower.contains("x11")
        || name_lower.contains("shared")
        || name_lower.contains("double-buffered")
        || name_lower.contains("chrome")
        || name_lower.contains("firefox")
        || name_lower.contains("colord")
        || name_lower.contains("gdm")
        || name_lower.contains("snap")
        || name_lower.contains("flatpak")
    {
        return true;
    }

    false
}

fn is_noisy_benign(comm: &str, filename: &str) -> bool {
    let comm_lower = comm.to_lowercase();
    let filename_lower = filename.to_lowercase();

    // XFCE and Kali panel widgets / scripts
    if comm_lower == "wrapper-2.0"
        || comm_lower.starts_with("xfce4-")
        || filename_lower.contains("xfce4-panel")
        || filename_lower.contains("genmon")
        || filename_lower.contains("vpnip.sh")
    {
        return true;
    }

    // Common background utility execution spams (e.g. from status bar or monitor scripts)
    if comm_lower == "grep"
        || comm_lower == "ip"
        || comm_lower == "cut"
        || comm_lower == "head"
        || comm_lower == "cat"
        || comm_lower == "sed"
        || comm_lower == "awk"
        || comm_lower == "tr"
        || comm_lower == "free"
        || comm_lower == "df"
        || comm_lower == "uptime"
        || comm_lower == "sensors"
    {
        return true;
    }

    false
}

#[derive(serde::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SensorStatus {
    Stopped,
    Starting,
    Running,
    Error,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    Learning,
    Enforcement,
}

pub struct AppState {
    status: Mutex<SensorStatus>,
    last_error: Mutex<Option<String>>,
    running_flag: Mutex<Option<Arc<AtomicBool>>>,
    task_handle: Mutex<Option<JoinHandle<()>>>,
    /// Phase 8: Handle for the aggregator flush task
    flush_task_handle: Mutex<Option<JoinHandle<()>>>,

    // Phase 6 Additions:
    engine_mode: Arc<tokio::sync::Mutex<EngineMode>>,
    baselines: Arc<tokio::sync::RwLock<std::collections::HashSet<(String, u32)>>>,
    connection_tracker: Arc<tokio::sync::RwLock<std::collections::HashMap<(String, u32), (Vec<std::time::Instant>, std::time::Instant)>>>,

    // Phase 9 Additions:
    baselines_path: Arc<tokio::sync::Mutex<Option<std::path::PathBuf>>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            status: Mutex::new(SensorStatus::Stopped),
            last_error: Mutex::new(None),
            running_flag: Mutex::new(None),
            task_handle: Mutex::new(None),
            flush_task_handle: Mutex::new(None),

            engine_mode: Arc::new(tokio::sync::Mutex::new(EngineMode::Learning)),
            baselines: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            connection_tracker: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),

            baselines_path: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

fn ip_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

#[tauri::command]
async fn start_sensor(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    // Check if already running
    {
        let status = state.status.lock().await;
        if *status == SensorStatus::Running {
            return Err("Sensor is already running".to_string());
        }
    }

    // Set status to starting
    {
        let mut status = state.status.lock().await;
        *status = SensorStatus::Starting;
    }
    let _ = app.emit("sentinella://status-change", "starting");

    log::info!("Starting Sentinella sensor...");

    // Load ebpf bytes
    let ebpf_bytes = match load_ebpf_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            let err_msg = format!("Failed to load eBPF bytecode: {}", e);
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    // Load Ebpf program
    let mut ebpf = match aya::Ebpf::load(&ebpf_bytes) {
        Ok(e) => e,
        Err(e) => {
            let err_msg = format!("Failed to load eBPF program: {}", e);
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    // Phase 8 diagnostic: enumerate all programs found in the eBPF object
    log::info!("eBPF programs found in object:");
    for (name, _prog) in ebpf.programs() {
        log::info!("  program: '{}'", name);
    }

    // Attach tracepoint program
    // With named sections (tracepoint/syscalls/<name>), Aya derives the program
    // name by stripping the type prefix. Try section-derived name first, then
    // fall back to the bare function name for backward compatibility.
    let execve_name = if ebpf.program("syscalls/sentinella_execve").is_some() {
        "syscalls/sentinella_execve"
    } else {
        "sentinella_execve"
    };
    log::info!("Loading execve program as '{}'", execve_name);
    let program: &mut aya::programs::TracePoint = match ebpf
        .program_mut(execve_name)
        .ok_or_else(|| format!("eBPF program '{}' not found", execve_name))
        .and_then(|p| p.try_into().map_err(|e| format!("Program is not a TracePoint: {}", e)))
    {
        Ok(p) => p,
        Err(err_msg) => {
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    if let Err(e) = program.load() {
        let err_msg = format!("Failed to load tracepoint program: {}", e);
        log::error!("{}", err_msg);
        let mut status = state.status.lock().await;
        *status = SensorStatus::Error;
        let mut last_error = state.last_error.lock().await;
        *last_error = Some(err_msg.clone());
        let _ = app.emit("sentinella://status-change", "error");
        return Err(err_msg);
    }

    if let Err(e) = program.attach("syscalls", "sys_enter_execve") {
        let err_msg = format!("Failed to attach tracepoint: {}", e);
        log::error!("{}", err_msg);
        let mut status = state.status.lock().await;
        *status = SensorStatus::Error;
        let mut last_error = state.last_error.lock().await;
        *last_error = Some(err_msg.clone());
        let _ = app.emit("sentinella://status-change", "error");
        return Err(err_msg);
    }

    // Attach memfd_create tracepoint program
    let memfd_name = if ebpf.program("syscalls/sentinella_memfd_create").is_some() {
        "syscalls/sentinella_memfd_create"
    } else {
        "sentinella_memfd_create"
    };
    log::info!("Loading memfd_create program as '{}'", memfd_name);
    let memfd_program_mut = match ebpf.program_mut(memfd_name) {
        Some(p) => p,
        None => {
            let err_msg = format!("eBPF program '{}' not found in object", memfd_name);
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    let memfd_program: &mut aya::programs::TracePoint = match memfd_program_mut
        .try_into()
        .map_err(|e| format!("Program is not a TracePoint: {}", e))
    {
        Ok(p) => p,
        Err(err_msg) => {
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    if let Err(e) = memfd_program.load() {
        let err_msg = format!("Failed to load memfd_create program: {}", e);
        log::error!("{}", err_msg);
        let mut status = state.status.lock().await;
        *status = SensorStatus::Error;
        let mut last_error = state.last_error.lock().await;
        *last_error = Some(err_msg.clone());
        let _ = app.emit("sentinella://status-change", "error");
        return Err(err_msg);
    }

    if let Err(e) = memfd_program.attach("syscalls", "sys_enter_memfd_create") {
        let err_msg = format!("Failed to attach memfd_create tracepoint: {}", e);
        log::error!("{}", err_msg);
        let mut status = state.status.lock().await;
        *status = SensorStatus::Error;
        let mut last_error = state.last_error.lock().await;
        *last_error = Some(err_msg.clone());
        let _ = app.emit("sentinella://status-change", "error");
        return Err(err_msg);
    }

    // Attach connect tracepoint program
    let connect_name = if ebpf.program("syscalls/sentinella_connect").is_some() {
        "syscalls/sentinella_connect"
    } else {
        "sentinella_connect"
    };
    log::info!("Loading connect program as '{}'", connect_name);
    let connect_program_mut = match ebpf.program_mut(connect_name) {
        Some(p) => p,
        None => {
            let err_msg = format!("eBPF program '{}' not found in object", connect_name);
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    let connect_program: &mut aya::programs::TracePoint = match connect_program_mut
        .try_into()
        .map_err(|e| format!("Program is not a TracePoint: {}", e))
    {
        Ok(p) => p,
        Err(err_msg) => {
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    if let Err(e) = connect_program.load() {
        let err_msg = format!("Failed to load connect program: {}", e);
        log::error!("{}", err_msg);
        let mut status = state.status.lock().await;
        *status = SensorStatus::Error;
        let mut last_error = state.last_error.lock().await;
        *last_error = Some(err_msg.clone());
        let _ = app.emit("sentinella://status-change", "error");
        return Err(err_msg);
    }

    if let Err(e) = connect_program.attach("syscalls", "sys_enter_connect") {
        let err_msg = format!("Failed to attach connect tracepoint: {}", e);
        log::error!("{}", err_msg);
        let mut status = state.status.lock().await;
        *status = SensorStatus::Error;
        let mut last_error = state.last_error.lock().await;
        *last_error = Some(err_msg.clone());
        let _ = app.emit("sentinella://status-change", "error");
        return Err(err_msg);
    }

    // Get RingBuf map
    let ring_buf = match aya::maps::RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| "Map 'EVENTS' not found in eBPF object".to_string())?
    ) {
        Ok(rb) => rb,
        Err(e) => {
            let err_msg = format!("Failed to create RingBuf from EVENTS map: {}", e);
            log::error!("{}", err_msg);
            let mut status = state.status.lock().await;
            *status = SensorStatus::Error;
            let mut last_error = state.last_error.lock().await;
            *last_error = Some(err_msg.clone());
            let _ = app.emit("sentinella://status-change", "error");
            return Err(err_msg);
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let running_flush = running.clone();
    let app_clone = app.clone();
    let app_flush = app.clone();

    let engine_mode_clone = state.engine_mode.clone();
    let baselines_clone = state.baselines.clone();
    let tracker_clone = state.connection_tracker.clone();
    let baselines_path_clone = state.baselines_path.clone();

    // Phase 8: Shared event aggregator for benign event deduplication
    let aggregator = Arc::new(EventAggregator::new());
    let aggregator_flush = aggregator.clone();

    // ── Flush task: drains the aggregator every AGGREGATION_WINDOW_MS ──
    let flush_task = tokio::spawn(async move {
        while running_flush.load(Ordering::Relaxed) {
            tokio::time::sleep(std::time::Duration::from_millis(AGGREGATION_WINDOW_MS)).await;
            let batch = aggregator_flush.flush().await;
            for ev in batch {
                if let Err(e) = app_flush.emit("sensor-telemetry", &ev) {
                    log::error!("Failed to emit aggregated event over Tauri IPC: {}", e);
                }
            }
        }
        // Final drain on shutdown
        let remaining = aggregator_flush.flush().await;
        for ev in remaining {
            let _ = app_flush.emit("sensor-telemetry", &ev);
        }
        log::info!("Aggregator flush task stopped.");
    });

    // Spawn task to read from ring buffer
    let task = tokio::spawn(async move {
        let _ebpf_keepalive = ebpf; // Keep Ebpf instance loaded so programs don't detach
        let mut async_fd = match tokio::io::unix::AsyncFd::new(ring_buf) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!("Failed to create AsyncFd for ring buffer: {}", e);
                return;
            }
        };

        let mut scanned_count = 0u64;
        let mut last_emitted_count = 0u64;
        let mut last_stats_emit = std::time::Instant::now();
        let mut last_alert_time = std::time::Instant::now();
        let mut alerts_in_current_second = 0;

        log::info!("Sentinella event loop started. Waiting for events...");
        while running_clone.load(Ordering::Relaxed) {
            let mut guard = match async_fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    log::error!("Error waiting for ring buffer readability: {}", e);
                    break;
                }
            };

            let mut processed = false;
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                processed = true;
                let data: &[u8] = item.as_ref();
                if data.len() < 4 {
                    continue;
                }

                let event_type = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                scanned_count += 1;

                if event_type == 3 {
                    // NetworkConnect event
                    if data.len() < std::mem::size_of::<sentinella_common::NetworkEvent>() {
                        continue;
                    }
                    let raw_event: sentinella_common::NetworkEvent = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const sentinella_common::NetworkEvent)
                    };

                    let comm = sentinella_common::bytes_to_str(&raw_event.comm).to_string();
                    let dest_ip = raw_event.dest_ip;
                    let dest_port = raw_event.dest_port;

                    let current_mode = {
                        let mode_lock = engine_mode_clone.lock().await;
                        *mode_lock
                    };

                    if current_mode == EngineMode::Learning {
                        // LEARNING MODE: profile IP into baseline Set
                        {
                            let mut baselines_lock = baselines_clone.write().await;
                            if baselines_lock.insert((comm.clone(), dest_ip)) {
                                // Save to disk
                                let path_lock = baselines_path_clone.lock().await;
                                if let Some(ref path) = *path_lock {
                                    if let Ok(serialized) = serde_json::to_string(&*baselines_lock) {
                                        let _ = std::fs::write(path, serialized);
                                    }
                                }
                            }
                        }

                        // Emit to GUI as Learned — route through aggregator (benign)
                        let details = format!("{}:{}", ip_to_string(dest_ip), dest_port);
                        let process_event = ProcessEvent {
                            timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
                            pid: raw_event.pid,
                            process: comm.clone(),
                            event_type: "Network Connect".to_string(),
                            details,
                            enforcement: "Learned".to_string(),
                            count: None,
                        };

                        aggregator.insert(process_event).await;
                    } else {
                        // ENFORCEMENT MODE: calculate beacons
                        let is_baselined = {
                            let baselines_lock = baselines_clone.read().await;
                            baselines_lock.contains(&(comm.clone(), dest_ip))
                        };

                        if !is_baselined {
                            let now = std::time::Instant::now();
                            
                            // Prune map every 1000 events to prevent memory leakage
                            static NETWORK_EVENT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                            let count = NETWORK_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
                            if count % 1000 == 0 {
                                let mut tracker_lock = tracker_clone.write().await;
                                tracker_lock.retain(|_, (_, last_updated)| {
                                    now.duration_since(*last_updated) < std::time::Duration::from_secs(300)
                                });
                            }

                            let mut tracker_lock = tracker_clone.write().await;
                            let entry = tracker_lock.entry((comm.clone(), dest_ip)).or_insert_with(|| (Vec::new(), now));
                            entry.1 = now; // update last seen
                            let timestamps = &mut entry.0;
                            timestamps.push(now);
                            if timestamps.len() > 5 {
                                timestamps.remove(0);
                            }

                            let mut is_beacon = false;
                            let mut avg_delta_secs = 0.0;

                            if timestamps.len() >= 3 {
                                let mut deltas = Vec::new();
                                for i in 1..timestamps.len() {
                                    let delta = timestamps[i].duration_since(timestamps[i-1]).as_secs_f64();
                                    deltas.push(delta);
                                }
                                
                                let sum: f64 = deltas.iter().sum();
                                let avg = sum / deltas.len() as f64;
                                
                                if avg >= 1.0 {
                                    let mut max_dev = 0.0;
                                    for &d in &deltas {
                                        let dev = (d - avg).abs();
                                        if dev > max_dev {
                                            max_dev = dev;
                                        }
                                    }
                                    let jitter = max_dev / avg;
                                    if jitter < 0.15 {
                                        is_beacon = true;
                                        avg_delta_secs = avg;
                                    }
                                }
                            }

                            let (event_type, enforcement) = if is_beacon {
                                (format!("C2 Beacon ({:.0}s Heartbeat)", avg_delta_secs), "Flagged (Alert)".to_string())
                            } else {
                                ("Network Connect".to_string(), "Observed".to_string())
                            };

                            let details = format!("{}:{}", ip_to_string(dest_ip), dest_port);
                            let process_event = ProcessEvent {
                                timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
                                pid: raw_event.pid,
                                process: comm.clone(),
                                event_type,
                                details,
                                enforcement,
                                count: None,
                            };

                            // ── SECURITY EXCEPTION: Beacon/Flagged events bypass aggregation ──
                            if is_beacon {
                                if let Err(e) = app_clone.emit("sensor-telemetry", &process_event) {
                                    log::error!("Failed to emit beacon alert over Tauri IPC: {}", e);
                                }
                            } else {
                                // Observed network connect — benign, aggregate it
                                aggregator.insert(process_event).await;
                            }
                        }
                    }
                } else {
                    // ExecEvent or FilelessExec event
                    if data.len() < std::mem::size_of::<sentinella_common::ExecEvent>() {
                        continue;
                    }
                    let raw_event: sentinella_common::ExecEvent = unsafe {
                        std::ptr::read_unaligned(data.as_ptr() as *const sentinella_common::ExecEvent)
                    };

                    let event_type_val = raw_event.event_type;
                    let is_restricted = is_restricted_comm(&raw_event.comm) || is_restricted_filename(&raw_event.filename);
                    let is_fileless = event_type_val == 2;

                    let comm = sentinella_common::bytes_to_str(&raw_event.comm);
                    let filename = sentinella_common::bytes_to_str(&raw_event.filename);

                    // Skip benign system memfds
                    if is_fileless && is_benign_memfd(comm, filename) {
                        continue;
                    }

                    // Skip noisy benign system utility executions to reduce CPU and UI clutter
                    if !is_restricted && !is_fileless && is_noisy_benign(comm, filename) {
                        continue;
                    }

                    if is_fileless || is_restricted {
                        // ── SECURITY EXCEPTION: Threat events ALWAYS bypass aggregation ──
                        let now = std::time::Instant::now();
                        if now.duration_since(last_alert_time) >= std::time::Duration::from_secs(1) {
                            last_alert_time = now;
                            alerts_in_current_second = 0;
                        }

                        if alerts_in_current_second < 10 {
                            alerts_in_current_second += 1;

                            let event_type = if is_fileless {
                                "Fileless Exec (Memfd)".to_string()
                            } else {
                                "Process Exec".to_string()
                            };

                            let enforcement = if is_fileless {
                                "Logged (Alert)".to_string()
                            } else {
                                "Blocked (SIGKILL)".to_string()
                            };

                            let details = if is_fileless {
                                filename.to_string()
                            } else {
                                if filename.is_empty() {
                                    comm.to_string()
                                } else {
                                    filename.to_string()
                                }
                            };

                            let process_event = ProcessEvent {
                                timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
                                pid: raw_event.pid,
                                process: comm.to_string(),
                                event_type,
                                details,
                                enforcement,
                                count: None,
                            };

                            // Emit IMMEDIATELY — never aggregated
                            if let Err(e) = app_clone.emit("sensor-telemetry", &process_event) {
                                log::error!("Failed to emit event over Tauri IPC: {}", e);
                            }
                        } else {
                            log::warn!("Rate-limiting threat alerts: exceeded 10 alerts per second.");
                        }
                    } else {
                        // ── BENIGN execve: route through aggregator ──
                        let details = if filename.is_empty() {
                            comm.to_string()
                        } else {
                            filename.to_string()
                        };

                        let process_event = ProcessEvent {
                            timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
                            pid: raw_event.pid,
                            process: comm.to_string(),
                            event_type: "Process Exec".to_string(),
                            details,
                            enforcement: "Observed".to_string(),
                            count: None,
                        };

                        aggregator.insert(process_event).await;
                    }
                }
            }

            guard.clear_ready();

            // Throttle statistics emission to at most once every 500ms to minimize IPC overhead
            if scanned_count != last_emitted_count && last_stats_emit.elapsed() >= std::time::Duration::from_millis(500) {
                if let Err(e) = app_clone.emit("sensor-stats", scanned_count) {
                    log::error!("Failed to emit stats over Tauri IPC: {}", e);
                }
                last_emitted_count = scanned_count;
                last_stats_emit = std::time::Instant::now();
            }

            // Prevent CPU busy-waiting if guard returns immediately but no events were processed
            if !processed {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        log::info!("Sentinella event loop stopped.");
    });

    // Update state to running
    {
        let mut status = state.status.lock().await;
        *status = SensorStatus::Running;
        let mut last_error = state.last_error.lock().await;
        *last_error = None;

        let mut run_flag = state.running_flag.lock().await;
        *run_flag = Some(running);

        let mut handle = state.task_handle.lock().await;
        *handle = Some(task);

        let mut flush_handle = state.flush_task_handle.lock().await;
        *flush_handle = Some(flush_task);
    }

    let _ = app.emit("sentinella://status-change", "running");
    log::info!("Sentinella sensor started successfully.");
    Ok("Sensor started".to_string())
}

#[tauri::command]
async fn stop_sensor(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut flag_lock = state.running_flag.lock().await;
    if let Some(flag) = flag_lock.take() {
        flag.store(false, Ordering::Relaxed);
    }

    let mut handle_lock = state.task_handle.lock().await;
    if let Some(handle) = handle_lock.take() {
        let _ = handle.await;
    }

    // Phase 8: Also stop the aggregator flush task
    let mut flush_lock = state.flush_task_handle.lock().await;
    if let Some(handle) = flush_lock.take() {
        let _ = handle.await;
    }

    let mut status = state.status.lock().await;
    *status = SensorStatus::Stopped;

    let _ = app.emit("sentinella://status-change", "stopped");
    log::info!("Sensor stopped via command.");
    Ok("Sensor stopped".to_string())
}

#[tauri::command]
async fn sensor_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let status = state.status.lock().await;
    let last_error = state.last_error.lock().await;

    Ok(serde_json::json!({
        "status": *status,
        "error": *last_error,
    }))
}

#[tauri::command]
async fn set_engine_mode(
    state: State<'_, AppState>,
    mode: EngineMode,
) -> Result<(), String> {
    let mut current_mode = state.engine_mode.lock().await;
    *current_mode = mode;
    log::info!("Engine mode set to: {:?}", mode);

    // Save engine mode config
    let path_lock = state.baselines_path.lock().await;
    if let Some(ref path) = *path_lock {
        if let Some(parent) = path.parent() {
            let config_path = parent.join("config.json");
            let config_content = serde_json::json!({
                "engine_mode": match mode {
                    EngineMode::Learning => "learning",
                    EngineMode::Enforcement => "enforcement",
                }
            });
            if let Ok(serialized) = serde_json::to_string(&config_content) {
                let _ = std::fs::write(config_path, serialized);
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn get_engine_mode(
    state: State<'_, AppState>,
) -> Result<EngineMode, String> {
    let mode = state.engine_mode.lock().await;
    Ok(*mode)
}

#[tauri::command]
fn check_privileges() -> Result<bool, String> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        Ok(uid == 0)
    }
    #[cfg(not(unix))]
    {
        Ok(true)
    }
}

/// Helper to load compiled eBPF bytecode.
fn load_ebpf_bytes() -> Result<Vec<u8>, String> {
    #[cfg(debug_assertions)]
    const EBPF_BYTES: &[u8] = include_bytes!("../../../../target/bpfel-unknown-none/debug/sentinella-ebpf");

    #[cfg(not(debug_assertions))]
    const EBPF_BYTES: &[u8] = include_bytes!("../../../../target/bpfel-unknown-none/release/sentinella-ebpf");

    Ok(EBPF_BYTES.to_vec())
}

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    log::info!("Starting Sentinella Desktop v{}", env!("CARGO_PKG_VERSION"));

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .setup(|app| {
            use tauri::Manager;
            let state = app.state::<AppState>();
            if let Ok(local_data_dir) = app.path().app_local_data_dir() {
                let _ = std::fs::create_dir_all(&local_data_dir);
                let baselines_path = local_data_dir.join("baselines.json");
                let config_path = local_data_dir.join("config.json");

                // Load baselines
                if baselines_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&baselines_path) {
                        if let Ok(loaded) = serde_json::from_str(&content) {
                            let mut lock = state.baselines.blocking_write();
                            *lock = loaded;
                            log::info!("Loaded persisted baselines from {:?}", baselines_path);
                        }
                    }
                }

                // Load config
                if config_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&config_path) {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(mode_str) = parsed.get("engine_mode").and_then(|v| v.as_str()) {
                                let mode = match mode_str {
                                    "enforcement" => EngineMode::Enforcement,
                                    _ => EngineMode::Learning,
                                };
                                let mut lock = state.engine_mode.blocking_lock();
                                *lock = mode;
                                log::info!("Loaded persisted engine mode: {:?}", mode);
                            }
                        }
                    }
                }

                // Save path to state
                let mut path_lock = state.baselines_path.blocking_lock();
                *path_lock = Some(baselines_path);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_sensor,
            stop_sensor,
            sensor_status,
            set_engine_mode,
            get_engine_mode,
            check_privileges,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to launch Sentinella Tauri application");
}


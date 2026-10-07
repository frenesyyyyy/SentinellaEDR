//! # Sentinella Desktop — Main Entry Point
//!
//! Launches the Tauri v2 application with the Sentinella eBPF sensor backend.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod aggregation;
mod policy;

use aggregation::{EventAggregator, ProcessEvent, AGGREGATION_WINDOW_MS};
use policy::{is_benign_memfd, is_noisy_benign, is_restricted_comm, is_restricted_filename};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

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

    flush_task_handle: Mutex<Option<JoinHandle<()>>>,

    engine_mode: Arc<tokio::sync::Mutex<EngineMode>>,
    baselines: Arc<tokio::sync::RwLock<std::collections::HashSet<(String, u32)>>>,
    connection_tracker: Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<(String, u32), (Vec<std::time::Instant>, std::time::Instant)>,
        >,
    >,

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
            connection_tracker: Arc::new(
                tokio::sync::RwLock::new(std::collections::HashMap::new()),
            ),

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
async fn start_sensor(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    {
        let status = state.status.lock().await;
        if *status == SensorStatus::Running {
            return Err("Sensor is already running".to_string());
        }
    }

    {
        let mut status = state.status.lock().await;
        *status = SensorStatus::Starting;
    }
    let _ = app.emit("sentinella://status-change", "starting");

    log::info!("Starting Sentinella sensor...");

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
        .and_then(|p| {
            p.try_into()
                .map_err(|e| format!("Program is not a TracePoint: {}", e))
        }) {
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

    let ring_buf = match aya::maps::RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| "Map 'EVENTS' not found in eBPF object".to_string())?,
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

    let aggregator = Arc::new(EventAggregator::new());
    let aggregator_flush = aggregator.clone();

    // Flush on a fixed interval; this is batching, not a per-event debounce.
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
                    // SAFETY: The size check covers the fixed-layout integer/byte fields;
                    // read_unaligned does not assume the ring-buffer slice is aligned.
                    let raw_event: sentinella_common::NetworkEvent = unsafe {
                        std::ptr::read_unaligned(
                            data.as_ptr() as *const sentinella_common::NetworkEvent
                        )
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
                                let path_lock = baselines_path_clone.lock().await;
                                if let Some(ref path) = *path_lock {
                                    if let Ok(serialized) = serde_json::to_string(&*baselines_lock)
                                    {
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

                            // Remove idle keys periodically; active keys retain at most five timestamps.
                            static NETWORK_EVENT_COUNT: std::sync::atomic::AtomicU64 =
                                std::sync::atomic::AtomicU64::new(0);
                            let count = NETWORK_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
                            if count % 1000 == 0 {
                                let mut tracker_lock = tracker_clone.write().await;
                                tracker_lock.retain(|_, (_, last_updated)| {
                                    now.duration_since(*last_updated)
                                        < std::time::Duration::from_secs(300)
                                });
                            }

                            let mut tracker_lock = tracker_clone.write().await;
                            let entry = tracker_lock
                                .entry((comm.clone(), dest_ip))
                                .or_insert_with(|| (Vec::new(), now));
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
                                    let delta = timestamps[i]
                                        .duration_since(timestamps[i - 1])
                                        .as_secs_f64();
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
                                (
                                    format!("C2 Beacon ({:.0}s Heartbeat)", avg_delta_secs),
                                    "Flagged (Alert)".to_string(),
                                )
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

                            // Emit beacon alerts without waiting for the display batch.
                            if is_beacon {
                                if let Err(e) = app_clone.emit("sensor-telemetry", &process_event) {
                                    log::error!(
                                        "Failed to emit beacon alert over Tauri IPC: {}",
                                        e
                                    );
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
                    // SAFETY: The size check covers the fixed-layout integer/byte fields;
                    // read_unaligned does not assume the ring-buffer slice is aligned.
                    let raw_event: sentinella_common::ExecEvent = unsafe {
                        std::ptr::read_unaligned(
                            data.as_ptr() as *const sentinella_common::ExecEvent
                        )
                    };

                    let event_type_val = raw_event.event_type;
                    let is_restricted = is_restricted_comm(&raw_event.comm)
                        || is_restricted_filename(&raw_event.filename);
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
                        // These alerts bypass batching, but still share the ten-per-second limit.
                        let now = std::time::Instant::now();
                        if now.duration_since(last_alert_time) >= std::time::Duration::from_secs(1)
                        {
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

                            if let Err(e) = app_clone.emit("sensor-telemetry", &process_event) {
                                log::error!("Failed to emit event over Tauri IPC: {}", e);
                            }
                        } else {
                            log::warn!(
                                "Rate-limiting threat alerts: exceeded 10 alerts per second."
                            );
                        }
                    } else {
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
            if scanned_count != last_emitted_count
                && last_stats_emit.elapsed() >= std::time::Duration::from_millis(500)
            {
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
async fn stop_sensor(app: AppHandle, state: State<'_, AppState>) -> Result<String, String> {
    let mut flag_lock = state.running_flag.lock().await;
    if let Some(flag) = flag_lock.take() {
        flag.store(false, Ordering::Relaxed);
    }

    let mut handle_lock = state.task_handle.lock().await;
    if let Some(handle) = handle_lock.take() {
        let _ = handle.await;
    }

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
async fn sensor_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let status = state.status.lock().await;
    let last_error = state.last_error.lock().await;

    Ok(serde_json::json!({
        "status": *status,
        "error": *last_error,
    }))
}

#[tauri::command]
async fn set_engine_mode(state: State<'_, AppState>, mode: EngineMode) -> Result<(), String> {
    let mut current_mode = state.engine_mode.lock().await;
    *current_mode = mode;
    log::info!("Engine mode set to: {:?}", mode);

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
async fn get_engine_mode(state: State<'_, AppState>) -> Result<EngineMode, String> {
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
    const EBPF_BYTES: &[u8] =
        include_bytes!("../../../../target/bpfel-unknown-none/debug/sentinella-ebpf");

    #[cfg(not(debug_assertions))]
    const EBPF_BYTES: &[u8] =
        include_bytes!("../../../../target/bpfel-unknown-none/release/sentinella-ebpf");

    Ok(EBPF_BYTES.to_vec())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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

                if baselines_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&baselines_path) {
                        if let Ok(loaded) = serde_json::from_str(&content) {
                            let mut lock = state.baselines.blocking_write();
                            *lock = loaded;
                            log::info!("Loaded persisted baselines from {:?}", baselines_path);
                        }
                    }
                }

                if config_path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&config_path) {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(mode_str) =
                                parsed.get("engine_mode").and_then(|v| v.as_str())
                            {
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

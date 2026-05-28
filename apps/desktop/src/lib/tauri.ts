/// Tauri API wrappers for Sentinella commands.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ProcessExecEvent, SensorStatusResponse, ProcessEvent } from "./types";

/** Start the eBPF sensor. */
export async function startSensor(): Promise<string> {
  return invoke<string>("start_sensor");
}

/** Stop the eBPF sensor. */
export async function stopSensor(): Promise<string> {
  return invoke<string>("stop_sensor");
}

/** Get current sensor status. */
export async function getSensorStatus(): Promise<SensorStatusResponse> {
  return invoke<SensorStatusResponse>("sensor_status");
}

/** Listen for process execution events from the backend. */
export async function onExecEvent(
  callback: (event: ProcessExecEvent) => void
): Promise<UnlistenFn> {
  return listen<ProcessExecEvent>("sentinella://exec-event", (e) => {
    callback(e.payload);
  });
}

/** Listen for real-time sensor telemetry events. */
export async function onSensorTelemetry(
  callback: (event: ProcessEvent) => void
): Promise<UnlistenFn> {
  return listen<ProcessEvent>("sensor-telemetry", (e) => {
    callback(e.payload);
  });
}

/** Listen for sensor status changes. */
export async function onStatusChange(
  callback: (status: string) => void
): Promise<UnlistenFn> {
  return listen<string>("sentinella://status-change", (e) => {
    callback(e.payload);
  });
}

/** Listen for process scanned count statistics. */
export async function onSensorStats(
  callback: (count: number) => void
): Promise<UnlistenFn> {
  return listen<number>("sensor-stats", (e) => {
    callback(e.payload);
  });
}

/** Set the engine mode (learning vs enforcement). */
export async function setEngineMode(mode: "learning" | "enforcement"): Promise<void> {
  return invoke<void>("set_engine_mode", { mode });
}

/** Get the current engine mode. */
export async function getEngineMode(): Promise<"learning" | "enforcement"> {
  return invoke<"learning" | "enforcement">("get_engine_mode");
}

/** Check if the application runs with root privileges. */
export async function checkPrivileges(): Promise<boolean> {
  return invoke<boolean>("check_privileges");
}


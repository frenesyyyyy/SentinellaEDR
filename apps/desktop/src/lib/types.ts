/// TypeScript types for Sentinella frontend events.

/** Process execution event from the Tauri backend. */
export interface ProcessExecEvent {
  /** ISO 8601 formatted timestamp */
  timestamp: string;
  /** Monotonic kernel timestamp in nanoseconds */
  timestamp_ns: number;
  /** Process ID */
  pid: number;
  /** Parent process ID (0 if unavailable) */
  ppid: number;
  /** User ID */
  uid: number;
  /** Process comm name */
  comm: string;
  /** Executable filename/path */
  filename: string;
  /** MITRE ATT&CK tactic */
  mitre_tactic: string;
  /** MITRE ATT&CK technique ID and name */
  mitre_technique: string;
}

/** Payload carried by the sensor-telemetry event */
export interface ProcessEvent {
  timestamp: string;
  pid: number;
  process: string;
  event_type: string;
  details: string;
  enforcement: string;
  /** Number of aggregated events (undefined or 1 = single event) */
  count?: number;
}

/** Sensor status values */
export type SensorStatus = "stopped" | "starting" | "running" | "error";

/** Response from the sensor_status command */
export interface SensorStatusResponse {
  status: SensorStatus;
  error: string | null;
}

import type { SensorStatus } from "../lib/types";

interface StatusBarProps {
  status: SensorStatus;
  error: string | null;
  eventCount: number;
  onStart: () => void;
  onStop: () => void;
  isLoading: boolean;
}

function statusDisplay(status: SensorStatus) {
  switch (status) {
    case "running":
      return { color: "text-emerald-400", label: "Sensor Running", dotClass: "bg-emerald-400 status-pulse" };
    case "starting":
      return { color: "text-amber-400", label: "Starting…", dotClass: "bg-amber-400 status-pulse" };
    case "error":
      return { color: "text-red-400", label: "Sensor Error", dotClass: "bg-red-400" };
    default:
      return { color: "text-slate-400", label: "Sensor Stopped", dotClass: "bg-slate-500" };
  }
}

export default function StatusBar({ status, error, eventCount, onStart, onStop, isLoading }: StatusBarProps) {
  const { color, label, dotClass } = statusDisplay(status);
  return (
    <div className="flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 bg-cyber-surface border-b border-cyber-border">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className={`w-2.5 h-2.5 rounded-full ${dotClass}`} />
            <span className={`text-sm font-medium ${color}`}>{label}</span>
          </div>
          {status === "running" && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-cyber-card border border-cyber-border">
              <span className="text-xs font-mono text-cyber-accent">{eventCount} events</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          {status === "stopped" || status === "error" ? (
            <button onClick={onStart} disabled={isLoading}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/25 disabled:opacity-50 transition-all">
              {isLoading ? "Starting…" : "Start Sensor"}
            </button>
          ) : (
            <button onClick={onStop} disabled={isLoading || status === "starting"}
              className="flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 disabled:opacity-50 transition-all">
              Stop Sensor
            </button>
          )}
        </div>
      </div>
      {error && (
        <div className="px-4 py-2 bg-red-500/10 border-b border-red-500/20">
          <p className="text-xs text-red-300 font-mono">{error}</p>
        </div>
      )}
    </div>
  );
}

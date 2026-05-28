import { useState, useEffect, useRef } from "react";
import type { ProcessExecEvent } from "../lib/types";

/** Maximum events to keep in memory */
const MAX_EVENTS = 500;

interface EventTableProps {
  events: ProcessExecEvent[];
}

/** Get the CSS class for a MITRE tactic badge */
function tacticBadgeClass(tactic: string): string {
  const normalized = tactic.toLowerCase().replace(/\s+/g, "-");
  const map: Record<string, string> = {
    execution: "badge-execution",
    discovery: "badge-discovery",
    persistence: "badge-persistence",
    "credential-access": "badge-credential-access",
    "defense-evasion": "badge-defense-evasion",
    "lateral-movement": "badge-lateral-movement",
    "command-and-control": "badge-command-and-control",
  };
  return map[normalized] || "badge-default";
}

/** Format ISO timestamp to a short display string */
function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    } as any);
  } catch {
    return iso;
  }
}

/** Truncate a filename to a max length for display */
function truncateFilename(filename: string, max: number = 50): string {
  if (filename.length <= max) return filename;
  return "…" + filename.slice(-(max - 1));
}

export default function EventTable({ events }: EventTableProps) {
  const tableRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    if (autoScroll && tableRef.current) {
      tableRef.current.scrollTop = tableRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  // Detect manual scroll
  const handleScroll = () => {
    if (!tableRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = tableRef.current;
    const isNearBottom = scrollHeight - scrollTop - clientHeight < 50;
    setAutoScroll(isNearBottom);
  };

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-cyber-border bg-cyber-surface/50">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Process Executions
          </h2>
          <span className="text-xs text-cyber-muted font-mono">
            {events.length} / {MAX_EVENTS}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {!autoScroll && (
            <button
              onClick={() => setAutoScroll(true)}
              className="text-xs px-2 py-1 rounded bg-cyber-accent/10 text-cyber-accent 
                         hover:bg-cyber-accent/20 transition-colors border border-cyber-accent/20"
            >
              ↓ Auto-scroll
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div
        ref={tableRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto overflow-x-auto min-h-0"
      >
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10">
            <tr className="bg-cyber-surface border-b border-cyber-border text-left">
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider w-28">
                Time
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider w-20">
                PID
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider w-20">
                PPID
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider w-16">
                UID
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider w-28">
                Comm
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider min-w-[200px]">
                Filename
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider w-36">
                MITRE Tactic
              </th>
              <th className="px-3 py-2 text-xs font-semibold text-cyber-muted uppercase tracking-wider min-w-[250px]">
                MITRE Technique
              </th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-16 text-center">
                  <div className="flex flex-col items-center gap-3">
                    <div className="w-12 h-12 rounded-full bg-cyber-card border border-cyber-border flex items-center justify-center">
                      <svg className="w-6 h-6 text-cyber-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    </div>
                    <p className="text-cyber-muted text-sm">
                      No events captured yet. Start the sensor to begin monitoring.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              events.map((event, i) => (
                <tr
                  key={`${event.timestamp_ns}-${event.pid}-${i}`}
                  className={`
                    border-b border-cyber-border/50 hover:bg-cyber-card/50 transition-colors
                    ${i === events.length - 1 ? "event-row-new" : ""}
                  `}
                >
                  <td className="px-3 py-1.5 font-mono text-xs text-slate-400">
                    {formatTime(event.timestamp)}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs text-cyan-400">
                    {event.pid}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs text-slate-500">
                    {event.ppid || "—"}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs text-slate-400">
                    {event.uid}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs text-emerald-400 font-medium">
                    {event.comm}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs text-slate-300" title={event.filename}>
                    {truncateFilename(event.filename)}
                  </td>
                  <td className="px-3 py-1.5">
                    <span className={`badge ${tacticBadgeClass(event.mitre_tactic)}`}>
                      {event.mitre_tactic}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-xs text-slate-400">
                    {event.mitre_technique}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

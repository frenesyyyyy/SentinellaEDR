import { useState, useEffect, useCallback, useRef } from "react";
import { startSensor, stopSensor, onSensorTelemetry, onStatusChange, getSensorStatus, onSensorStats, getEngineMode, setEngineMode, checkPrivileges } from "./lib/tauri";
import type { ProcessEvent, SensorStatus } from "./lib/types";
import logo from "./sentinellalogo.png";
import icon from "./sentinellaico.png";

const MAX_EVENTS = 300;

export default function App() {
  const [status, setStatus] = useState<SensorStatus>("stopped");
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<ProcessEvent[]>([]);
  const [scannedCount, setScannedCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [engineMode, setEngineModeState] = useState<"learning" | "enforcement">("learning");

  // Loading / Splash Screen states
  const [showLoading, setShowLoading] = useState(true);
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [loadingStatus, setLoadingStatus] = useState("Initializing EDR systems...");
  const [loadingError, setLoadingError] = useState<string | null>(null);


  const handleToggleEngineMode = async () => {
    const nextMode = engineMode === "learning" ? "enforcement" : "learning";
    try {
      await setEngineMode(nextMode);
      setEngineModeState(nextMode);
    } catch (e: any) {
      console.error("Failed to toggle engine mode", e);
    }
  };

  // Loading simulator & privilege validation
  useEffect(() => {
    let progress = 0;
    const interval = setInterval(async () => {
      progress += 2;
      if (progress <= 100) {
        setLoadingProgress(progress);
        if (progress === 20) {
          setLoadingStatus("Verifying system dependencies...");
        } else if (progress === 40) {
          setLoadingStatus("Checking kernel privileges...");
          try {
            const isRoot = await checkPrivileges();
            if (!isRoot) {
              setLoadingError("Sentinella requires root privileges (run via sudo) to load eBPF tracepoint probes.");
              clearInterval(interval);
              return;
            }
          } catch (e) {
            setLoadingError("Error checking privileges.");
            clearInterval(interval);
            return;
          }
        } else if (progress === 70) {
          setLoadingStatus("Loading local baseline configurations...");
        } else if (progress === 90) {
          setLoadingStatus("Attaching kernel EDR probes...");
          try {
            const currentStatus = await getSensorStatus();
            if (currentStatus.status !== "running") {
              await startSensor();
              setStatus("running");
            }
          } catch (e: any) {
            console.warn("Failed to auto-start EDR sensor:", e);
          }
        }
      } else {
        clearInterval(interval);
        setTimeout(() => {
          setShowLoading(false);
        }, 150);
      }
    }, 15);

    return () => clearInterval(interval);
  }, []);

  const gridEndRef = useRef<HTMLDivElement>(null);
  const gridBodyRef = useRef<HTMLDivElement>(null);

  // Sync scroll to bottom when new telemetry arrives
  useEffect(() => {
    if (autoScroll && gridEndRef.current) {
      gridEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, autoScroll]);

  // Handle scroll detection
  const handleScroll = () => {
    if (!gridBodyRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = gridBodyRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 30;
    setAutoScroll(isAtBottom);
  };

  // Listen for backend events, stats, & status changes
  useEffect(() => {
    const unlisteners: (() => void)[] = [];
    const pendingEvents: ProcessEvent[] = [];

    // Listen for ProcessEvent telemetry stream and queue them
    onSensorTelemetry((event) => {
      pendingEvents.push(event);
    }).then((u) => unlisteners.push(u));

    // Listen for total scanned count statistics
    onSensorStats((count) => {
      setScannedCount(count);
    }).then((u) => unlisteners.push(u));

    // Throttling: batch commit pending events every 500ms to eliminate UI thrashing
    const throttleInterval = setInterval(() => {
      if (pendingEvents.length > 0) {
        const chunk = [...pendingEvents];
        pendingEvents.length = 0; // Clear queue
        
        setEvents((prev) => {
          const next = [...prev, ...chunk];
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
        });
      }
    }, 500);

    // Listen for status changes
    onStatusChange((s) => {
      setStatus(s as SensorStatus);
      if (s === "running") setIsLoading(false);
      if (s === "error") setIsLoading(false);
    }).then((u) => unlisteners.push(u));

    // Fetch initial status on mount
    getSensorStatus().then((res) => {
      setStatus(res.status);
      if (res.error) setError(res.error);
    }).catch((e) => {
      console.error("Failed to fetch initial sensor status", e);
    });

    // Fetch initial engine mode on mount
    getEngineMode().then((mode) => {
      setEngineModeState(mode);
    }).catch((e) => {
      console.error("Failed to fetch initial engine mode", e);
    });

    return () => {
      unlisteners.forEach((u) => u());
      clearInterval(throttleInterval);
    };
  }, []);

  const handleStart = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await startSensor();
    } catch (e: any) {
      setError(typeof e === "string" ? e : e.message || "Unknown error");
      setStatus("error");
      setIsLoading(false);
    }
  }, []);

  const handleStop = useCallback(async () => {
    setIsLoading(true);
    try {
      await stopSensor();
      setStatus("stopped");
    } catch (e: any) {
      setError(typeof e === "string" ? e : e.message || "Unknown error");
    }
    setIsLoading(false);
  }, []);

  const handleToggleSensor = () => {
    if (status === "running") {
      handleStop();
    } else {
      handleStart();
    }
  };

  const clearLogs = () => {
    setEvents([]);
  };

  const isRunning = status === "running";
  const isStarting = status === "starting";

  if (showLoading) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-zinc-950 text-zinc-100 font-sans select-none">
        <div className="flex flex-col items-center max-w-md p-8 bg-zinc-900/40 rounded-xl border border-zinc-800/60 backdrop-blur-md shadow-2xl">
          <img src={icon} className="h-16 w-16 object-contain mb-4 animate-pulse" alt="Sentinella Icon" />
          <h1 className="text-xl font-bold tracking-tight text-white uppercase font-sans">
            Sentinella
          </h1>
          <span className="text-[9px] text-zinc-500 font-mono tracking-widest uppercase mt-1">
            Kernel-Native EDR Sensor
          </span>

          <div className="w-64 h-1.5 bg-zinc-950 rounded-full overflow-hidden border border-zinc-800/80 mt-6 relative">
            <div 
              className="h-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.6)] transition-all duration-75 ease-out"
              style={{ width: `${loadingProgress}%` }}
            />
          </div>
          <span className="text-[10px] text-cyan-400 font-mono font-bold mt-2">{loadingProgress}%</span>

          {loadingError ? (
            <div className="mt-4 p-3 bg-red-950/20 border border-red-900/40 rounded text-center">
              <span className="text-xs text-red-400 font-mono block">
                [INIT_FAILED]
              </span>
              <span className="text-[11px] text-zinc-300 font-sans mt-1 block max-w-xs">
                {loadingError}
              </span>
            </div>
          ) : (
            <span className="text-[10px] text-zinc-400 font-mono tracking-wider uppercase mt-4 animate-pulse">
              {loadingStatus}
            </span>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-zinc-950 text-zinc-100 font-sans overflow-hidden select-none">
      {/* Topbar */}
      <div className="flex items-center justify-between px-6 py-4 bg-zinc-900 border-b border-zinc-800/80 shadow-md">
        <div className="flex items-center gap-4">
          <div className="bg-zinc-950 p-2 rounded border border-zinc-800/60 flex items-center justify-center">
            <img src={logo} className="h-10 object-contain" alt="Sentinella Logo" />
          </div>
          <div className="flex flex-col">
            <span className="text-md font-bold tracking-tight text-white font-sans uppercase">
              Sentinella
            </span>
            <span className="text-[9px] text-zinc-400 font-mono tracking-widest uppercase">
              Security Agent & telemetry console
            </span>
          </div>

          {/* status badge */}
          {isRunning && (
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300 text-[9px] font-semibold tracking-wider font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)]"></span>
              ACTIVE
            </div>
          )}

          {isStarting && (
            <span className="text-[10px] text-zinc-400 font-mono tracking-wider animate-pulse">
              [STARTING...]
            </span>
          )}

          {status === "stopped" && (
            <span className="text-[10px] text-zinc-500 font-mono tracking-wider">
              [PAUSED]
            </span>
          )}
        </div>

        {/* Topbar Actions */}
        <div className="flex items-center gap-3">
          {/* Mode Toggle Switch */}
          <div className="flex items-center gap-2.5 bg-zinc-950 px-3 py-1.5 rounded border border-zinc-800 select-none">
            <span className={`text-[10px] font-mono tracking-wider font-semibold transition-colors duration-200
              ${engineMode === "learning" ? "text-cyan-400" : "text-zinc-500"}`}>
              LEARN
            </span>
            <button
              onClick={handleToggleEngineMode}
              className={`relative w-9 h-5 rounded-full transition-colors duration-300 focus:outline-none border
                ${engineMode === "learning"
                  ? "bg-zinc-900 border-zinc-700"
                  : "bg-zinc-900 border-zinc-700"
                }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-3.5 h-3.5 rounded-full transition-transform duration-300
                  ${engineMode === "learning"
                    ? "bg-cyan-400 translate-x-0"
                    : "bg-zinc-400 translate-x-4"
                  }`}
              />
            </button>
            <span className={`text-[10px] font-mono tracking-wider font-semibold transition-colors duration-200
              ${engineMode === "enforcement" ? "text-white" : "text-zinc-500"}`}>
              ENFORCE
            </span>
          </div>

          {/* Clear Logs Button */}
          <button 
            onClick={clearLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded border border-zinc-800 hover:border-zinc-700 bg-zinc-950 text-zinc-300 hover:text-white transition-all select-none"
            title="Clear threat event console"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
            Clear Threats
          </button>

          {/* Pause/Resume Sensor Button */}
          <button
            onClick={handleToggleSensor}
            disabled={isStarting || isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded border border-zinc-800 hover:border-zinc-700 bg-zinc-950 text-zinc-300 hover:text-white transition-all select-none disabled:opacity-50"
          >
            {isRunning ? (
              <>
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Pause Sensor
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Resume Sensor
              </>
            )}
          </button>
        </div>
      </div>

      {/* Stats Summary Line (Minimalistic Overview) */}
      <div className="flex items-center justify-between px-6 py-3 bg-zinc-900/60 border-b border-zinc-800/80 select-text">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-zinc-400 font-mono uppercase tracking-wider font-semibold">Scanned Executions:</span>
            <span className="text-xs text-zinc-200 font-mono font-bold tracking-tight bg-zinc-950 px-2.5 py-0.5 rounded border border-zinc-800">
              {scannedCount.toLocaleString()}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-zinc-400 font-mono uppercase tracking-wider font-semibold">Flagged Alerts:</span>
            <span className="text-xs text-zinc-200 font-mono font-bold tracking-tight bg-zinc-950 px-2.5 py-0.5 rounded border border-zinc-800">
              {events.length}
            </span>
          </div>
        </div>
        <div className="text-[10px] text-zinc-500 font-mono tracking-wider">
          SYSTEM LAYER MONITORS: EXECVE | CONNECT | MEMFD_CREATE
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="px-6 py-2 bg-red-950/15 border-b border-red-900/30">
          <p className="text-xs text-red-400 font-mono select-text font-medium">
            [SYS_ERROR] {error}
          </p>
        </div>
      )}

      {/* Telemetry Grid Container */}
      <div 
        ref={gridBodyRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto overflow-x-auto min-h-0 bg-zinc-950"
      >
        <table className="w-full text-left border-collapse table-fixed min-w-[900px]">
          <thead className="sticky top-0 z-10 bg-zinc-900/95 shadow-sm">
            <tr className="border-b border-zinc-850 text-zinc-400 text-[10px] font-bold font-mono tracking-wider uppercase">
              <th className="py-3 px-6 w-32 font-medium border-r border-zinc-850/60">Time</th>
              <th className="py-3 px-6 w-20 font-medium border-r border-zinc-850/60">PID</th>
              <th className="py-3 px-6 w-44 font-medium border-r border-zinc-850/60">Process</th>
              <th className="py-3 px-6 w-52 font-medium border-r border-zinc-850/60">Event Type</th>
              <th className="py-3 px-6 font-medium border-r border-zinc-850/60">Details</th>
              <th className="py-3 px-6 w-44 font-medium">Enforcement</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-32 text-center">
                  <div className="flex flex-col items-center gap-2">
                    <span className="font-mono text-[10px] text-zinc-500 tracking-widest uppercase">
                      {isRunning 
                        ? "Sensor active. Listening for events..." 
                        : "Sensor stopped"
                      }
                    </span>
                  </div>
                </td>
              </tr>
            ) : (
              events.map((event, index) => {
                const isBlocked = event.enforcement.includes("Blocked");
                const isFlagged = event.enforcement.includes("Flagged");
                const isLearned = event.enforcement.includes("Learned");
                
                let rowBg = "hover:bg-zinc-900/40";
                let textClass = "text-zinc-300";
                
                if (isBlocked || isFlagged) {
                  rowBg = "bg-red-950/5 hover:bg-red-950/10";
                  textClass = "text-zinc-200";
                } else if (isLearned) {
                  rowBg = "bg-cyan-950/5 hover:bg-cyan-950/10";
                  textClass = "text-zinc-200";
                }

                return (
                  <tr 
                    key={index}
                    className={`border-b border-zinc-900/80 transition-colors duration-150 font-mono text-xs ${rowBg} ${textClass}`}
                  >
                    <td className="py-2.5 px-6 border-r border-zinc-900/60 whitespace-nowrap opacity-60">
                      {event.timestamp}
                    </td>
                    <td className="py-2.5 px-6 border-r border-zinc-900/60 whitespace-nowrap opacity-80">
                      {event.pid}
                    </td>
                    <td className="py-2.5 px-6 border-r border-zinc-900/60 font-semibold truncate select-text" title={event.process}>
                      <div className="flex items-center gap-2">
                        <span className="truncate">{event.process}</span>
                        {event.count && event.count > 1 && (
                          <span
                            className="inline-flex items-center px-1.5 py-0 rounded-full text-[9px] font-bold font-mono tracking-wide whitespace-nowrap"
                            style={{
                              background: 'rgba(34, 211, 238, 0.12)',
                              color: '#22d3ee',
                              border: '1px solid rgba(34, 211, 238, 0.25)',
                              boxShadow: '0 0 8px rgba(34, 211, 238, 0.10)',
                              lineHeight: '1.4',
                            }}
                          >
                            ×{event.count}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-6 border-r border-zinc-900/60 truncate font-semibold uppercase text-[10px] tracking-wide" title={event.event_type}>
                      {event.event_type}
                    </td>
                    <td className="py-2.5 px-6 border-r border-zinc-900/60 truncate select-text text-zinc-400" title={event.details}>
                      {event.details}
                    </td>
                    <td className="py-2.5 px-6 font-bold">
                      <div className="flex items-center gap-2">
                        {isBlocked || isFlagged ? (
                          <>
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.5)]"></span>
                            <span className="text-[10px] text-red-400 uppercase tracking-wider">{event.enforcement}</span>
                          </>
                        ) : isLearned ? (
                          <>
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(34,211,238,0.5)]"></span>
                            <span className="text-[10px] text-cyan-400 uppercase tracking-wider">{event.enforcement}</span>
                          </>
                        ) : (
                          <>
                            <span className="w-1.5 h-1.5 rounded-full bg-zinc-500"></span>
                            <span className="text-[10px] text-zinc-400 uppercase tracking-wider">{event.enforcement}</span>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
        
        {/* End Reference for Autoscroll */}
        <div ref={gridEndRef} />
      </div>

      {/* Footer — Brand Attribution */}
      <div className="flex items-center justify-center px-6 py-1.5 bg-zinc-900/40 border-t border-zinc-800/60">
        <span
          className="text-[10px] tracking-widest uppercase"
          style={{
            fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", monospace',
            color: 'rgba(161, 161, 170, 0.45)',
            letterSpacing: '0.18em',
          }}
        >
          © Frenesy
        </span>
      </div>
    </div>
  );
}


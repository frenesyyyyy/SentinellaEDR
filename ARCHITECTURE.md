# Architecture

This describes the current source, including places where the prototype's layers
are not yet fully separated.

## Components

| Component | Responsibility | Boundary |
| --- | --- | --- |
| `crates/sentinella-common` | Fixed-layout event records and byte decoding | `no_std`; integer fields and bounded byte arrays |
| `crates/sentinella-ebpf` | `execve`, `memfd_create`, IPv4 `connect` capture; restricted-name signal policy | Kernel tracepoints, fixed offsets, 256 KiB ring buffer |
| `apps/desktop/src-tauri/src/main.rs` | Attach probes, decode events, network baseline/timing logic, state and Tauri commands | Owns the active desktop sensor lifecycle |
| `aggregation.rs` | Collect display events and drain batches | Key is process name plus event type; latest payload wins |
| `policy.rs` | Desktop name/path filters | Pure heuristics; separate from the kernel signal policy |
| `apps/desktop/src/App.tsx` | Subscribe to telemetry/status and update the display | Batches pending events every 500 ms |
| `crates/sentinella-core` | Alternative exec-only loader, event conversion, static MITRE mapping | Present in the workspace; not the desktop's active event path |
| `xtask` | Build the separate eBPF crate | Uses its pinned nightly toolchain and root target directory |

## Event contract

`ExecEvent` carries the numeric kind, PID, PPID, UID, monotonic timestamp,
16-byte process name and 256-byte filename or memfd name. `NetworkEvent` carries
the same identity fields plus an IPv4 address and port. PPID is currently zero.
The consumer checks record size before an unaligned read. This is a shared
in-process ABI, not a versioned external protocol; both sides must be rebuilt
together when the layout changes.

The probe reports syscall entry, not syscall success. At exec entry, `comm` can
still identify the calling process. No argument vector is captured.

## Processing and delivery

The desktop owns the loaded `Ebpf` object inside the reader task. Dropping it
detaches the probes. Tokio `AsyncFd` waits for ring-buffer readability and the
reader drains available records before clearing readiness.

Network Learning mode stores `(comm, destination IP)` pairs in memory and JSON.
Enforcement mode examines unbaselined pairs, retaining at most five timestamps.
Three or more observations, mean spacing of at least one second and maximum
relative deviation below 0.15 trigger a beacon label. This is timing-based
classification; it does not establish command-and-control traffic.

Non-alert events enter 250 ms batches. Different PIDs, paths or destinations can
collapse if their process name and event type match; only the latest details
survive. Beacon events go straight to IPC. Restricted-name and memfd alerts also
bypass batching, but share a ten-alerts-per-second limit. The UI separately
batches rendering, so direct IPC is not a zero-latency display guarantee.

## State and shutdown

The Tauri state contains the status, error, task handles, mode, network baseline
and timing tracker. Local application data stores `baselines.json` and
`config.json`; telemetry itself is not a durable audit trail.

Stopping sets a flag and awaits the tasks. A reader waiting for readiness has no
explicit cancellation wakeup, so shutdown can stall on an idle sensor. A flush
task has a final drain, but shutdown is not a proven lossless protocol.

## Trust boundary

The application runs with substantial privileges. The kernel policy attempts a
signal independently of UI mode and ignores its return value. The UI renders
labels inferred from names, not verified enforcement outcomes. Tauri's CSP is
currently unset. These constraints matter before using the prototype beyond a VM.

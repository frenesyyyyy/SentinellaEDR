# Known limitations

## Behavior to understand before running

- **Learning is not passive.** The kernel attempts SIGKILL for `nc`, `ncat`,
  `netcat` and `socat` independently of the desktop mode. No mode map connects the
  UI switch to that policy. The signal result is ignored, so "Blocked" can be misleading.
- Name matching can terminate legitimate tools and can be bypassed by renaming.
  `comm` at exec entry may still be the caller's name. This is not preventative
  containment with a verified outcome.
- Capture covers `execve`, `memfd_create` and IPv4 `connect`, not `execveat`,
  IPv6, argv, process ancestry or successful syscall return values. Memfd creation
  is not proof that code executed from memory. Allowlist filters are hardcoded.
- Restricted-name and memfd alerts share a ten-per-second limit. Ring-buffer
  reservation failure silently drops records. Neither layer provides complete
  loss accounting; the displayed scan count is not a count of all kernel activity.

## Lifecycle and storage

- A stopped reader can remain blocked waiting for ring-buffer readiness. Concurrent
  starts are not serialized across the whole startup operation; some errors can
  leave stale status. These are open lifecycle issues.
- JSON persistence uses synchronous writes and ignores some errors. Writes are
  not atomic and the baseline has no retention bound. There is no durable event
  history, centralized collection, schema migration or authenticated policy service.
- Aggregation groups by process name and event type, not PID, command arguments or
  network destination. It preserves the latest payload and a count, not all evidence.
- Connection timing uses process name plus IP, so unrelated processes can share
  history. It omits ports from the key and cannot validate a network threat.

## Coverage and packaging

- The desktop does not use the core MITRE classifier. The core's general shell
  branch also precedes its Unix-shell-specific branch; the latter is shadowed.
- Fixed tracepoint offsets assume the intended Linux ABI. Kernel/version and
  permission compatibility require actual VM testing, beyond compilation in CI.
- Root privileges and an unset Tauri CSP need a security review before deployment.
- Source package versions are `0.1.0`; historical release labels differ. No new
  binary release is implied by this cleanup.
- No reproducible CPU/latency benchmark, production false-positive measurement,
  or comprehensive runtime integration suite is included.

## Follow-up order

1. Separate audit-only mode from enforcement and report actual signal outcomes.
2. Add cancellable lifecycle transitions and failure/status tests.
3. Account for kernel/display drops and make persistence bounded and atomic.
4. Validate capture and policy in a disposable Linux VM matrix, then measure load.

These items are deliberately not bundled into the behavior-preserving cleanup.

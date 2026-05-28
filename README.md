<![CDATA[<div align="center">

<img src="sentinellaico.png" alt="Sentinella Logo" width="128" height="128">

# 🛡️ Sentinella

**Real-Time Kernel-Level Threat Telemetry for Linux**

[![Rust](https://img.shields.io/badge/Rust-stable%20%2B%20nightly-orange?logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Aya%200.13-blueviolet)](https://aya-rs.dev/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8D8?logo=tauri)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-lightgrey?logo=linux)](https://kernel.org/)

<br/>

> **Zero-dependency, kernel-native endpoint detection and response.**
> Sentinella intercepts syscalls at the eBPF layer, maps behaviors to
> MITRE ATT&CK in real time, and enforces threat policy — all from a
> single lightweight desktop application.

</div>

---

## ✨ Features

| Capability | Description |
|---|---|
| 🔬 **Kernel Tracepoints** | Hooks `sys_enter_execve`, `sys_enter_memfd_create`, and `sys_enter_connect` via eBPF tracepoints — zero kernel module required |
| 🗺️ **MITRE ATT&CK Mapping** | Automatic tactic & technique classification for every observed process execution |
| 🧬 **Fileless Execution Detection** | Detects `memfd_create` abuse used by in-memory payloads; filters known-benign system memfds (PulseAudio, Wayland, browsers) |
| 🌐 **Network Connect Monitoring** | Captures outbound `connect()` syscalls with IP:port resolution |
| 🎯 **C2 Beacon Detection** | Behavioral jitter analysis over sliding windows identifies periodic callbacks with ≤15% timing deviation |
| 🔒 **Enforcement Engine** | Dual-mode operation: **Learning** (baseline profiling) → **Enforcement** (anomaly detection & SIGKILL blocking for restricted tools) |
| 🛡️ **Restricted Tool Blocking** | Auto-kills execution of `nc`, `ncat`, `netcat`, `socat` with enforcement-level response |
| ⚡ **Event Flood Aggregation** | 250ms debounce window collapses duplicate benign events from high-thread applications (Firefox, Chrome) — threat alerts always bypass aggregation |
| 🖥️ **Live Dark-Mode Dashboard** | Tauri v2 + React UI with real-time telemetry grid, auto-scroll, stats counters, and threat highlighting |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Linux Kernel                            │
│                                                              │
│  sys_enter_execve ──┐                                        │
│  sys_enter_memfd  ──┼──▶ eBPF Tracepoint Programs            │
│  sys_enter_connect ─┘         │                              │
│                               ▼                              │
│                        BPF Ring Buffer                       │
└────────────────────────────┬─────────────────────────────────┘
                             │  zero-copy
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                   Rust Userspace (Aya)                        │
│                                                              │
│  ┌─────────────┐  ┌───────────────┐  ┌───────────────────┐   │
│  │ MITRE Engine│  │ Beacon Detect │  │ Event Aggregator  │   │
│  │ (Tactic Map)│  │ (Jitter Anal.)│  │ (250ms Debounce)  │   │
│  └──────┬──────┘  └───────┬───────┘  └────────┬──────────┘   │
│         └─────────────────┼───────────────────┘              │
│                           ▼                                  │
│               Tauri v2 IPC (Event Emitter)                   │
└───────────────────────────┬──────────────────────────────────┘
                            │  JSON events
                            ▼
┌──────────────────────────────────────────────────────────────┐
│              React + TypeScript Frontend                      │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────────┐   │
│  │ Topbar   │ │ Stats Bar│ │ Telemetry  │ │ Threat       │   │
│  │ Controls │ │ Counters │ │ Grid Table │ │ Highlighting │   │
│  └──────────┘ └──────────┘ └────────────┘ └──────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## 📦 Project Structure

```
sentinella/
├── crates/
│   ├── sentinella-common/     # Shared #[repr(C)] event structs (no_std)
│   ├── sentinella-ebpf/       # eBPF tracepoint programs (BPF target)
│   └── sentinella-core/       # Userspace event processing & MITRE mapping
├── apps/
│   └── desktop/
│       ├── src/               # React + TypeScript + Tailwind frontend
│       └── src-tauri/         # Tauri v2 Rust backend (sensor, aggregator)
├── xtask/                     # Build orchestration for eBPF compilation
├── install.sh                 # One-line installer script
└── Cargo.toml                 # Workspace root
```

| Crate | Purpose |
|---|---|
| `sentinella-common` | Shared `ExecEvent`, `NetworkEvent` structs — `#[repr(C)]`, `no_std` compatible |
| `sentinella-ebpf` | eBPF tracepoint probes compiled to `bpfel-unknown-none` target |
| `sentinella-core` | MITRE ATT&CK mapping engine, event classification |
| `sentinella-tauri` | Tauri v2 backend: sensor lifecycle, enforcement, event aggregation |
| `apps/desktop` | React dashboard: real-time telemetry grid, threat visualization |

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Minimum |
|---|---|
| Linux Kernel | ≥ 5.8 (BPF ring buffer) |
| Capabilities | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` (or root) |
| Architecture | x86_64 |
| Rust | stable + nightly toolchains |
| Node.js | ≥ 18 |

### Build & Run

```bash
# 1 — Install system dependencies (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y \
  clang llvm libelf-dev linux-headers-$(uname -r) \
  pkg-config build-essential zlib1g-dev libssl-dev \
  libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev \
  patchelf libgtk-3-dev libayatana-appindicator3-dev

# 2 — Rust toolchain setup
rustup install stable nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

# 3 — Build eBPF probes
cargo xtask build-ebpf

# 4 — Build frontend + Tauri
cd apps/desktop && npm install && cd ../..
cargo build

# 5 — Launch with privileges
cd apps/desktop
sudo -E npm run tauri dev
```

### One-Line Install (Kali/Debian)

```bash
curl -sSL https://raw.githubusercontent.com/frenesy/sentinella/main/install.sh | sudo bash
```

---

## 🖥️ Usage

### Sensor Controls

| Action | Description |
|---|---|
| **Resume Sensor** | Attaches eBPF probes and begins real-time telemetry |
| **Pause Sensor** | Detaches probes, stops event collection |
| **LEARN / ENFORCE** | Toggle between baseline learning and active enforcement |
| **Clear Threats** | Clears the telemetry grid (does not affect the kernel sensor) |

### Testing Detection

```bash
# Trigger execve telemetry
/bin/ls && /usr/bin/whoami && /bin/bash -lc "echo test"

# Trigger restricted tool enforcement (will be SIGKILL'd in Enforcement mode)
nc -h 2>/dev/null
ncat --version 2>/dev/null

# Trigger fileless execution alert (memfd_create)
# Any non-whitelisted memfd_create call will be flagged
```

### Event Aggregation (Phase 8)

When high-thread applications like Firefox spawn hundreds of `execve` calls:

- **Benign events** are buffered for 250ms and deduplicated by process name
- The UI shows a cyan **×45** pill badge indicating 45 collapsed executions
- **Threat events** (Blocked, Flagged, FilelessExec, C2 Beacon) **always bypass** aggregation and appear immediately

---

## 🔐 Security Model

```
Event Type              │ Aggregated? │ Delay │ Action
────────────────────────┼─────────────┼───────┼──────────────────
Benign execve           │ ✅ Yes      │ 250ms │ Observed
Benign network connect  │ ✅ Yes      │ 250ms │ Learned / Observed
Restricted tool (nc..)  │ ❌ Never    │ 0ms   │ Blocked (SIGKILL)
Fileless exec (memfd)   │ ❌ Never    │ 0ms   │ Logged (Alert)
C2 Beacon detected      │ ❌ Never    │ 0ms   │ Flagged (Alert)
Unknown network (enf.)  │ ✅ Yes      │ 250ms │ Observed
```

> **Guarantee**: No threat event is ever delayed, grouped, or suppressed.
> The aggregator only touches events classified as benign.

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|---|---|---|
| Execution | T1059 — Command & Scripting Interpreter | execve tracing |
| Defense Evasion | T1620 — Reflective Code Loading | memfd_create monitoring |
| Command & Control | T1071 — Application Layer Protocol | connect() + beacon jitter |
| Persistence | T1053 — Scheduled Task/Job | execve context analysis |
| Discovery | T1082 — System Information Discovery | process execution patterns |

---

## 📊 Development Roadmap

- [x] **Phase 1** — Process execution telemetry (`execve`)
- [x] **Phase 2** — Tauri v2 desktop app with live UI
- [x] **Phase 3** — MITRE ATT&CK tactic/technique mapping
- [x] **Phase 4** — Fileless execution detection (`memfd_create`)
- [x] **Phase 5** — Network connect monitoring (`connect`)
- [x] **Phase 6** — Learning/Enforcement engine with restricted tool blocking
- [x] **Phase 7** — C2 beacon detection via jitter analysis
- [x] **Phase 8** — Event flood aggregation & GUI branding
- [ ] **Phase 9** — File integrity monitoring (FIM)
- [ ] **Phase 10** — Container/K8s context enrichment
- [ ] **Phase 11** — Cloud CNAPP integration & SIEM export

---

## ⚙️ Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`) |
| `CARGO_WORKSPACE_DIR` | auto-detect | Override workspace root for eBPF bytecode lookup |

---

## 🧪 Development

```bash
# Run with debug logging
RUST_LOG=debug sudo -E npm run tauri dev

# Build eBPF in release mode
cargo xtask build-ebpf --release

# Type-check frontend
cd apps/desktop && npx tsc --noEmit

# Format Rust code
cargo fmt --all
```

---

## 📜 License

MIT — See [LICENSE](LICENSE) for details.

---

## 📋 Properties & Licensable Product

- **Product Name**: Sentinella
- **Logo / Icon**: [sentinellaico.png](sentinellaico.png)
- **Version**: 0.1.0
- **Publisher**: Frenesy
- **Copyright**: Copyright © 2026 Sentinella Contributors
- **License**: MIT
- **Scope**: Open-source EDR platform and telemetry sensor (Licensable product with full permission to run, modify, and distribute).

---

<div align="center">

**Built with ❤️ by Frenesy**

*Kernel-native endpoint security, no agents required.*

</div>
]]>

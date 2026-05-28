//! # MITRE ATT&CK Mapping
//!
//! Phase 1 static classification of process executions to MITRE ATT&CK framework.
//! This is intentionally simple — pattern matching on comm/filename to identify
//! common execution techniques.
//!
//! Phase 2 will add:
//! - Parent-child chain analysis
//! - Argument inspection
//! - Container context
//! - Behavioral sequence detection

/// A MITRE ATT&CK mapping result.
#[derive(Debug, Clone)]
pub struct MitreMapping {
    /// MITRE ATT&CK Tactic (e.g., "Execution", "Discovery")
    pub tactic: &'static str,
    /// MITRE ATT&CK Technique ID + name
    pub technique: &'static str,
}

impl MitreMapping {
    /// Classify a process execution event based on comm name and filename.
    ///
    /// This is a static heuristic for Phase 1. It checks the process name
    /// against known patterns to assign the most likely MITRE technique.
    pub fn classify(comm: &str, filename: &str) -> Self {
        let comm_lower = comm.to_lowercase();
        let filename_lower = filename.to_lowercase();

        // --- Execution: Command and Scripting Interpreter ---
        // T1059 — shells and interpreters
        if is_shell(&comm_lower) || is_shell_path(&filename_lower) {
            return MitreMapping {
                tactic: "Execution",
                technique: "T1059 - Command and Scripting Interpreter",
            };
        }

        // T1059.004 — Unix Shell specifically
        if comm_lower == "sh" || comm_lower == "dash" || comm_lower == "zsh" || comm_lower == "fish" {
            return MitreMapping {
                tactic: "Execution",
                technique: "T1059.004 - Unix Shell",
            };
        }

        // T1059.006 — Python
        if comm_lower.starts_with("python") {
            return MitreMapping {
                tactic: "Execution",
                technique: "T1059.006 - Python",
            };
        }

        // T1059.001 — PowerShell (unlikely on Linux, but defensive)
        if comm_lower == "pwsh" || comm_lower == "powershell" {
            return MitreMapping {
                tactic: "Execution",
                technique: "T1059.001 - PowerShell",
            };
        }

        // --- Discovery ---
        // T1082 — System Information Discovery
        if matches!(comm_lower.as_str(), "uname" | "hostnamectl" | "lsb_release" | "cat" | "dmidecode") {
            return MitreMapping {
                tactic: "Discovery",
                technique: "T1082 - System Information Discovery",
            };
        }

        // T1083 — File and Directory Discovery
        if matches!(comm_lower.as_str(), "ls" | "find" | "locate" | "tree" | "stat" | "file") {
            return MitreMapping {
                tactic: "Discovery",
                technique: "T1083 - File and Directory Discovery",
            };
        }

        // T1033 — System Owner/User Discovery
        if matches!(comm_lower.as_str(), "whoami" | "id" | "who" | "w" | "users" | "last" | "finger") {
            return MitreMapping {
                tactic: "Discovery",
                technique: "T1033 - System Owner/User Discovery",
            };
        }

        // T1049 — System Network Connections Discovery
        if matches!(comm_lower.as_str(), "netstat" | "ss" | "lsof") {
            return MitreMapping {
                tactic: "Discovery",
                technique: "T1049 - System Network Connections Discovery",
            };
        }

        // T1057 — Process Discovery
        if matches!(comm_lower.as_str(), "ps" | "top" | "htop" | "pgrep" | "pidof") {
            return MitreMapping {
                tactic: "Discovery",
                technique: "T1057 - Process Discovery",
            };
        }

        // --- Persistence ---
        // T1053.003 — Cron
        if matches!(comm_lower.as_str(), "crontab" | "cron" | "at" | "atd") {
            return MitreMapping {
                tactic: "Persistence",
                technique: "T1053.003 - Cron",
            };
        }

        // T1543.002 — Systemd Service
        if matches!(comm_lower.as_str(), "systemctl" | "systemd" | "service") {
            return MitreMapping {
                tactic: "Persistence",
                technique: "T1543.002 - Systemd Service",
            };
        }

        // --- Credential Access ---
        // T1003 — OS Credential Dumping (detection, not execution)
        if matches!(comm_lower.as_str(), "passwd" | "shadow" | "chpasswd") {
            return MitreMapping {
                tactic: "Credential Access",
                technique: "T1003 - OS Credential Dumping",
            };
        }

        // --- Defense Evasion ---
        // T1070 — Indicator Removal
        if matches!(comm_lower.as_str(), "shred" | "wipe" | "srm") {
            return MitreMapping {
                tactic: "Defense Evasion",
                technique: "T1070 - Indicator Removal",
            };
        }

        // --- Lateral Movement ---
        // T1021.004 — Remote Services: SSH
        if matches!(comm_lower.as_str(), "ssh" | "scp" | "sftp" | "sshd") {
            return MitreMapping {
                tactic: "Lateral Movement",
                technique: "T1021.004 - SSH",
            };
        }

        // --- Command and Control ---
        // T1105 — Ingress Tool Transfer
        if matches!(comm_lower.as_str(), "curl" | "wget" | "fetch" | "aria2c") {
            return MitreMapping {
                tactic: "Command and Control",
                technique: "T1105 - Ingress Tool Transfer",
            };
        }

        // --- Fallback: Generic Execution ---
        MitreMapping {
            tactic: "Execution",
            technique: "T1106 - Native API (Process Execution)",
        }
    }
}

/// Check if a comm name is a known shell.
fn is_shell(comm: &str) -> bool {
    matches!(
        comm,
        "bash" | "sh" | "dash" | "zsh" | "fish" | "csh" | "tcsh" | "ksh" | "ash"
    )
}

/// Check if a filename path points to a known shell.
fn is_shell_path(filename: &str) -> bool {
    filename.ends_with("/bash")
        || filename.ends_with("/sh")
        || filename.ends_with("/dash")
        || filename.ends_with("/zsh")
        || filename.ends_with("/fish")
        || filename.ends_with("/csh")
        || filename.ends_with("/tcsh")
        || filename.ends_with("/ksh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_classification() {
        let m = MitreMapping::classify("bash", "/bin/bash");
        assert_eq!(m.tactic, "Execution");
        assert!(m.technique.contains("T1059"));
    }

    #[test]
    fn test_discovery_ls() {
        let m = MitreMapping::classify("ls", "/bin/ls");
        assert_eq!(m.tactic, "Discovery");
        assert!(m.technique.contains("T1083"));
    }

    #[test]
    fn test_whoami() {
        let m = MitreMapping::classify("whoami", "/usr/bin/whoami");
        assert_eq!(m.tactic, "Discovery");
        assert!(m.technique.contains("T1033"));
    }

    #[test]
    fn test_unknown_falls_to_execution() {
        let m = MitreMapping::classify("myapp", "/opt/myapp/bin/myapp");
        assert_eq!(m.tactic, "Execution");
        assert!(m.technique.contains("T1106"));
    }

    #[test]
    fn test_curl_c2() {
        let m = MitreMapping::classify("curl", "/usr/bin/curl");
        assert_eq!(m.tactic, "Command and Control");
        assert!(m.technique.contains("T1105"));
    }

    #[test]
    fn test_ssh_lateral() {
        let m = MitreMapping::classify("ssh", "/usr/bin/ssh");
        assert_eq!(m.tactic, "Lateral Movement");
        assert!(m.technique.contains("T1021"));
    }
}

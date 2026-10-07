//! Name-based display filters. These are heuristics, not trust decisions.

#[cfg(test)]
mod tests {
    use super::*;

    fn filename(value: &str) -> [u8; 256] {
        let mut bytes = [0; 256];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        bytes
    }

    #[test]
    fn restricted_filename_requires_an_exact_basename() {
        for name in ["nc", "/usr/bin/ncat", "/opt/netcat", "/usr/bin/socat"] {
            assert!(is_restricted_filename(&filename(name)), "{name}");
        }
        for name in ["", "/usr/bin/sync", "ncat-helper", "/opt/socat.txt"] {
            assert!(!is_restricted_filename(&filename(name)), "{name}");
        }
    }

    #[test]
    fn memfd_filter_preserves_case_folding_and_empty_name_exception() {
        assert!(is_benign_memfd("Firefox", "payload"));
        assert!(is_benign_memfd("unknown", ""));
        assert!(!is_benign_memfd("unknown", "payload"));
    }

    #[test]
    fn noise_filter_distinguishes_known_utilities_from_unknown_programs() {
        assert!(is_noisy_benign("GREP", "/usr/bin/grep"));
        assert!(!is_noisy_benign("worker", "/opt/worker"));
    }
}

pub(crate) fn is_restricted_comm(comm: &[u8; 16]) -> bool {
    let s = sentinella_common::bytes_to_str(comm);
    matches!(s, "nc" | "ncat" | "netcat" | "socat")
}

pub(crate) fn is_restricted_filename(filename: &[u8; 256]) -> bool {
    let s = sentinella_common::bytes_to_str(filename);
    s == "nc"
        || s.ends_with("/nc")
        || s == "ncat"
        || s.ends_with("/ncat")
        || s == "netcat"
        || s.ends_with("/netcat")
        || s == "socat"
        || s.ends_with("/socat")
}

pub(crate) fn is_benign_memfd(comm: &str, name: &str) -> bool {
    let comm_lower = comm.to_lowercase();
    if comm_lower.contains("pulse")
        || comm_lower.contains("pipewire")
        || comm_lower.contains("chrome")
        || comm_lower.contains("chromium")
        || comm_lower.contains("firefox")
        || comm_lower.contains("gnome")
        || comm_lower.contains("wayland")
        || comm_lower.contains("xorg")
        || comm_lower.contains("dbus")
        || comm_lower.contains("systemd")
        || comm_lower.contains("glycin")
        || comm_lower.contains("gvfs")
        || comm_lower.contains("gdm")
        || comm_lower.contains("packagekit")
        || comm_lower.contains("sudo")
        || comm_lower.contains("bash")
        || comm_lower.contains("zsh")
        || comm_lower.contains("fish")
    {
        return true;
    }

    let name_lower = name.to_lowercase();
    if name_lower.is_empty()
        || name_lower.contains("pulse")
        || name_lower.contains("pipewire")
        || name_lower.contains("wayland")
        || name_lower.contains("mesa")
        || name_lower.contains("glycin")
        || name_lower.contains("x11")
        || name_lower.contains("shared")
        || name_lower.contains("double-buffered")
        || name_lower.contains("chrome")
        || name_lower.contains("firefox")
        || name_lower.contains("colord")
        || name_lower.contains("gdm")
        || name_lower.contains("snap")
        || name_lower.contains("flatpak")
    {
        return true;
    }

    false
}

pub(crate) fn is_noisy_benign(comm: &str, filename: &str) -> bool {
    let comm_lower = comm.to_lowercase();
    let filename_lower = filename.to_lowercase();

    // XFCE and Kali panel widgets / scripts
    if comm_lower == "wrapper-2.0"
        || comm_lower.starts_with("xfce4-")
        || filename_lower.contains("xfce4-panel")
        || filename_lower.contains("genmon")
        || filename_lower.contains("vpnip.sh")
    {
        return true;
    }

    // Common background utility execution spams (e.g. from status bar or monitor scripts)
    if comm_lower == "grep"
        || comm_lower == "ip"
        || comm_lower == "cut"
        || comm_lower == "head"
        || comm_lower == "cat"
        || comm_lower == "sed"
        || comm_lower == "awk"
        || comm_lower == "tr"
        || comm_lower == "free"
        || comm_lower == "df"
        || comm_lower == "uptime"
        || comm_lower == "sensors"
    {
        return true;
    }

    false
}

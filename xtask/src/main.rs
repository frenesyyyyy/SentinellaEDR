//! # xtask — Build orchestration for Sentinella eBPF programs
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!
//! This compiles the sentinella-ebpf crate for the `bpfel-unknown-none` target
//! using the nightly toolchain, and places the output in `target/bpfel-unknown-none/`.
//!
//! The userspace crate (sentinella-core) then embeds the compiled eBPF object
//! via `include_bytes_aligned!`.

use std::process::Command;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "xtask", about = "Sentinella build orchestration")]
enum Cli {
    /// Build the eBPF program for bpfel-unknown-none
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let ebpf_dir = workspace_root.join("crates").join("sentinella-ebpf");

    // Verify the eBPF crate exists
    if !ebpf_dir.join("Cargo.toml").exists() {
        bail!(
            "eBPF crate not found at {}. Expected crates/sentinella-ebpf/Cargo.toml",
            ebpf_dir.display()
        );
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir);
    cmd.env_remove("RUSTUP_TOOLCHAIN");

    // Use nightly toolchain (enforced by rust-toolchain.toml in the ebpf crate)
    cmd.args(["build", "--target", "bpfel-unknown-none"]);

    // Build from source since there's no pre-built std for bpfel
    cmd.arg("-Z").arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    // Set the target directory to the workspace target so sentinella-core can find it
    let target_dir = workspace_root.join("target");
    cmd.env("CARGO_TARGET_DIR", &target_dir);

    println!("=== Building eBPF program ===");
    println!("  crate: {}", ebpf_dir.display());
    println!("  target: bpfel-unknown-none");
    println!("  profile: {}", if release { "release" } else { "dev" });
    println!("  output: {}", target_dir.display());
    println!();

    let status = cmd
        .status()
        .context("Failed to execute cargo build for eBPF. Is nightly toolchain installed?")?;

    if !status.success() {
        bail!("eBPF build failed with status: {}", status);
    }

    let profile = if release { "release" } else { "debug" };
    let output_path = target_dir
        .join("bpfel-unknown-none")
        .join(profile)
        .join("sentinella-ebpf");

    println!();
    println!("=== eBPF build complete ===");
    println!("  output: {}", output_path.display());
    println!();
    println!("The userspace crate will embed this via include_bytes_aligned!");

    Ok(())
}

/// Find the workspace root by looking for the top-level Cargo.toml with [workspace].
fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .context("Failed to run `cargo locate-project`")?;

    if !output.status.success() {
        bail!("cargo locate-project failed");
    }

    let path = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in cargo locate-project output")?;
    let path = PathBuf::from(path.trim());

    // locate-project returns the Cargo.toml path; we want the directory
    Ok(path
        .parent()
        .context("Cargo.toml has no parent directory")?
        .to_path_buf())
}

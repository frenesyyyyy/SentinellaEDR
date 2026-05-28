#!/usr/bin/env -S cargo +stable script
//! Quick diagnostic: load eBPF ELF and check what aya-obj sees.
//! Run: cargo +stable run --example check_ebpf

use std::fs;

fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/target/bpfel-unknown-none/debug/sentinella-ebpf");
    println!("Loading: {}", path);
    
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Cannot read {}: {}", path, e);
            std::process::exit(1);
        }
    };
    println!("File size: {} bytes", bytes.len());
    
    let mut ebpf = match aya::Ebpf::load(&bytes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Ebpf::load failed: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("\n=== Programs found ===");
    for (name, prog) in ebpf.programs() {
        println!("  '{}' -> type: {:?}", name, prog.prog_type());
    }
    
    println!("\n=== Maps found ===");
    for (name, _map) in ebpf.maps() {
        println!("  '{}'", name);
    }
    
    // Try loading each program
    for prog_name in &["sentinella_execve", "sentinella_memfd_create", "sentinella_connect",
                        "syscalls/sentinella_execve", "syscalls/sentinella_memfd_create", "syscalls/sentinella_connect"] {
        match ebpf.program_mut(prog_name) {
            Some(prog) => {
                let tp: Result<&mut aya::programs::TracePoint, _> = prog.try_into();
                match tp {
                    Ok(tp) => {
                        match tp.load() {
                            Ok(()) => println!("  '{}' -> LOADED OK", prog_name),
                            Err(e) => println!("  '{}' -> LOAD FAILED: {}", prog_name, e),
                        }
                    }
                    Err(e) => println!("  '{}' -> Not a TracePoint: {}", prog_name, e),
                }
            }
            None => println!("  '{}' -> NOT FOUND", prog_name),
        }
    }
}

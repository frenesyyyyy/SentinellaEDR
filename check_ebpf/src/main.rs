use std::fs;
use aya::Ebpf;
use aya::programs::TracePoint;

fn test_load(path: &str) {
    println!("\n========================================");
    println!("Testing ELF: {}", path);
    println!("========================================");

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("Failed to read {}: {}", path, e);
            return;
        }
    };

    let mut ebpf = match Ebpf::load(&bytes) {
        Ok(e) => e,
        Err(e) => {
            println!("Ebpf::load failed: {}", e);
            return;
        }
    };

    println!("Programs found:");
    for (name, _) in ebpf.programs() {
        println!("  '{}'", name);
    }

    // List of tracepoints to test loading
    let program_names = [
        "sentinella_execve",
        "sentinella_memfd_create",
        "sentinella_connect",
    ];

    for name in &program_names {
        println!("Attempting to load '{}'...", name);
        
        // With section names, program name might have syscalls/ prefix
        let actual_name = if ebpf.program(&format!("syscalls/{}", name)).is_some() {
            format!("syscalls/{}", name)
        } else {
            name.to_string()
        };

        match ebpf.program_mut(&actual_name) {
            Some(prog) => {
                let tp: Result<&mut TracePoint, _> = prog.try_into();
                match tp {
                    Ok(tp) => {
                        match tp.load() {
                            Ok(()) => println!("  SUCCESS: loaded '{}'", name),
                            Err(e) => println!("  FAILED: loaded '{}': {}", name, e),
                        }
                    }
                    Err(e) => println!("  FAILED: program '{}' is not a TracePoint: {}", name, e),
                }
            }
            None => println!("  FAILED: program '{}' not found in ELF", name),
        }
    }
}

fn main() {
    test_load("target/bpfel-unknown-none/debug/sentinella-ebpf");
    test_load("target/bpfel-unknown-none/release/sentinella-ebpf");
}

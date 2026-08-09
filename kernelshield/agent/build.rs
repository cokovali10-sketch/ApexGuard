//! build.rs — генерация:
//!   1) prost+tonic кода из ../../proto/events.proto (через protoc-bin-vendored);
//!   2) libbpf-rs skeleton (kernelshield.skel.rs) из .bpf.o (если объект собран).
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // ---- 1. Proto → prost + tonic (client-only) ----
    println!("cargo:rerun-if-changed=../../proto/events.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    tonic_build::configure()
        .out_dir(&out_dir)
        .protoc_path(protoc)
        .build_client(true)
        .build_server(false)
        .compile_protos(&["../../proto/events.proto"], &["../../proto"])?;

    // ---- 2. BPF skeleton ----
    let bpf_o = PathBuf::from("../../probes/kernelshield.bpf.o");
    let skel_out = PathBuf::from("src/bpf/kernelshield.skel.rs");
    if bpf_o.exists() {
        println!("cargo:rerun-if-changed=../../probes/kernelshield.bpf.o");
        libbpf_cargo::SkeletonBuilder::new()
            .source(bpf_o)
            .build_and_generate(&skel_out)?;
    } else {
        println!("cargo:warning=../../probes/kernelshield.bpf.o not found — run `make -C ../../kernelshield all` first. BPF attach disabled.");
    }

    println!("cargo:rerun-if-changed=src/ringbuf.rs");
    println!("cargo:rerun-if-changed=src/cgroup.rs");
    println!("cargo:rerun-if-changed=src/grpc_client.rs");
    Ok(())
}

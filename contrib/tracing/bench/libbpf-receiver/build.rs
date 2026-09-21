use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/net_msgs.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("net_msgs.skel.rs");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set");

    // Pre-generated vmlinux.h from the `vmlinux` crate, so no bpftool is needed.
    let mut clang_args: Vec<OsString> = vec![
        OsString::from("-I"),
        vmlinux::include_path_root().join(&arch).into_os_string(),
    ];
    // usdt.bpf.h includes <linux/errno.h> -> <asm/errno.h>. On Debian/Ubuntu
    // the asm headers live in the multiarch directory, which clang does not
    // search when targeting bpf, so add it explicitly when it exists.
    let multiarch = PathBuf::from(format!("/usr/include/{arch}-linux-gnu"));
    if multiarch.join("asm").is_dir() {
        clang_args.push(OsString::from("-I"));
        clang_args.push(multiarch.into_os_string());
    }
    // BPF_CFLAGS adds extra clang arguments, e.g. an include path providing
    // <linux/errno.h> on systems without /usr/include (NixOS).
    if let Ok(extra) = env::var("BPF_CFLAGS") {
        clang_args.extend(extra.split_whitespace().map(OsString::from));
    }

    let mut builder = SkeletonBuilder::new();
    builder.source(SRC).clang_args(clang_args);
    // BPF_CLANG selects the clang used for the BPF target (e.g. an unwrapped
    // clang on NixOS, where the wrapped one injects x86-only hardening flags).
    if let Some(clang) = env::var_os("BPF_CLANG") {
        builder.clang(clang);
    }
    builder
        .build_and_generate(&out)
        .expect("failed to build the BPF skeleton");
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=BPF_CFLAGS");
}

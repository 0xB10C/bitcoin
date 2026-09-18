//! Compiles the Bitcoin Core IPC schemas (src/ipc/capnp/*.capnp) and
//! libmultiprocess's proxy.capnp into Rust with capnpc. The schemas are copied
//! into OUT_DIR first so that the absolute `import "/mp/proxy.capnp"` can be
//! rewritten to a relative one, like the bitcoin-capnp-types crate does.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCHEMAS: &[&str] = &[
    "common", "echo", "handler", "init", "mining", "rpc", "tracing",
];

fn capnp_include_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    // <prefix>/bin/capnp -> <prefix>/include (needed for /capnp/c++.capnp on
    // systems where capnp is not installed under /usr).
    if let Ok(out) = Command::new("which").arg("capnp").output() {
        if let Ok(path) = String::from_utf8(out.stdout) {
            let path = PathBuf::from(path.trim());
            if let Ok(real) = fs::canonicalize(&path) {
                if let Some(prefix) = real.parent().and_then(Path::parent) {
                    let inc = prefix.join("include");
                    if inc.join("capnp").join("c++.capnp").exists() {
                        dirs.push(inc);
                    }
                }
            }
        }
    }
    for d in ["/usr/include", "/usr/local/include"] {
        let p = PathBuf::from(d);
        if p.join("capnp").join("c++.capnp").exists() {
            dirs.push(p);
        }
    }
    dirs
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo = manifest
        .join("../../../..")
        .canonicalize()
        .expect("repo root");
    let src_dir = repo.join("src/ipc/capnp");
    let mp_dir = repo.join("src/ipc/libmultiprocess/include/mp");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let schemas = out.join("schemas");
    fs::create_dir_all(&schemas).unwrap();

    let mut files = Vec::new();
    for name in SCHEMAS {
        let from = src_dir.join(format!("{name}.capnp"));
        let to = schemas.join(format!("{name}.capnp"));
        let text = fs::read_to_string(&from).unwrap_or_else(|e| panic!("{}: {e}", from.display()));
        fs::write(
            &to,
            text.replace("import \"/mp/proxy.capnp\"", "import \"proxy.capnp\""),
        )
        .unwrap();
        println!("cargo:rerun-if-changed={}", from.display());
        files.push(to);
    }
    let proxy_from = mp_dir.join("proxy.capnp");
    let proxy_to = schemas.join("proxy.capnp");
    fs::copy(&proxy_from, &proxy_to).unwrap_or_else(|e| panic!("{}: {e}", proxy_from.display()));
    println!("cargo:rerun-if-changed={}", proxy_from.display());
    files.push(proxy_to);

    let mut cmd = capnpc::CompilerCommand::new();
    cmd.src_prefix(&schemas);
    for dir in capnp_include_dirs() {
        cmd.import_path(dir);
    }
    for f in &files {
        cmd.file(f);
    }
    cmd.run()
        .expect("capnp schema compilation failed (is the `capnp` compiler installed?)");
}

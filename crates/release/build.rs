//! Embeds the release owner's current root-signed trust policy as the floor a
//! fresh installation may not go below (see docs/releases.md).
use std::{env, fs, path::PathBuf};

fn main() {
    let release = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../release");
    let policy = release.join("sirinvpn-release-trust.json");
    let signature = release.join("sirinvpn-release-trust.sig.json");
    println!("cargo:rerun-if-changed={}", policy.display());
    println!("cargo:rerun-if-changed={}", signature.display());
    let source = match (policy.is_file(), signature.is_file()) {
        (true, true) => format!(
            "Some((include_bytes!({:?}).as_slice(), include_bytes!({:?}).as_slice()))",
            fs::canonicalize(&policy).unwrap(),
            fs::canonicalize(&signature).unwrap()
        ),
        (false, false) => {
            println!(
                "cargo:warning=no embedded floor: release/sirinvpn-release-trust.json and .sig.json are absent, so a fresh installation accepts any policy the bundled root signed"
            );
            "None".to_owned()
        }
        _ => panic!(
            "release/ must hold both sirinvpn-release-trust.json and sirinvpn-release-trust.sig.json, or neither"
        ),
    };
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("embedded_trust_floor.rs");
    fs::write(out, source).unwrap();
}

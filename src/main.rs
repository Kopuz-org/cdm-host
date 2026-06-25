//! PoC: load the system Widevine CDM and emit a real ChromeCDM license
//! challenge from a CENC pssh box.
//!
//! Run: `cargo run --bin cdm_challenge -- <libwidevinecdm.so> <pssh_box_file>`
//! The pssh file is the raw CENC pssh box (e.g. decoded from a Spotify
//! seektable's `pssh.widevine`).

use base64::Engine;

const BRAVE_CDM: &str = "/home/umceko/.config/BraveSoftware/Brave-Browser/WidevineCdm/4.10.3050.0/_platform_specific/linux_x64/libwidevinecdm.so";

fn main() -> anyhow::Result<()> {
    let so = std::env::args().nth(1).unwrap_or_else(|| BRAVE_CDM.to_string());
    let pssh_path = std::env::args().nth(2).unwrap_or_else(|| "/tmp/pssh.bin".to_string());
    let pssh = std::fs::read(&pssh_path)?;
    println!("CDM: {so}\npssh box: {} bytes", pssh.len());

    cdm_host::open(&so)?;
    println!("✓ CDM opened + initialized");

    let challenge = cdm_host::challenge(&pssh)?;
    println!("✓ challenge generated: {} bytes", challenge.len());

    // quick sanity: a Widevine SignedMessage starts with field 1 (type) varint.
    let looks_chromecdm = challenge.windows(9).any(|w| w == b"ChromeCDM");
    println!("  contains \"ChromeCDM\": {looks_chromecdm}");
    println!("  base64: {}", base64::engine::general_purpose::STANDARD.encode(&challenge));
    Ok(())
}

//! PoC: load the system Widevine CDM and emit a real ChromeCDM license
//! challenge from a CENC pssh box.
//!
//! Run: `cargo run --bin cdm_challenge -- [libwidevinecdm.so] <pssh_box_file>`
//! The pssh file is the raw CENC pssh box (e.g. decoded from a Spotify
//! seektable's `pssh.widevine`). With no `.so` arg, a CDM is located on the
//! system automatically.

use base64::Engine;

use cdm_host::{vendor, CdmHost};

fn main() -> anyhow::Result<()> {
    let so = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .or_else(vendor::locate_system_cdm)
        .ok_or_else(|| anyhow::anyhow!("no CDM path given and none found on the system"))?;
    let pssh_path = std::env::args().nth(2).unwrap_or_else(|| "/tmp/pssh.bin".to_string());
    let pssh = std::fs::read(&pssh_path)?;
    println!("CDM: {}\npssh box: {} bytes", so.display(), pssh.len());

    let cdm = CdmHost::open(&so)?;
    println!("✓ CDM opened + initialized");

    let challenge = cdm.challenge(&pssh)?;
    println!("✓ challenge generated: {} bytes", challenge.len());

    // quick sanity: a Widevine SignedMessage starts with field 1 (type) varint.
    let looks_chromecdm = challenge.windows(9).any(|w| w == b"ChromeCDM");
    println!("  contains \"ChromeCDM\": {looks_chromecdm}");
    println!("  base64: {}", base64::engine::general_purpose::STANDARD.encode(&challenge));
    Ok(())
}

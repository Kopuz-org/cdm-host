//! Sourcing a `libwidevinecdm.so` for [`CdmHost::install_or_open`](crate::CdmHost::install_or_open).
//!
//! Order of preference: a CDM already in the target dir → copy one from an
//! installed Chromium-family app (no network) → (with the `download` feature)
//! fetch it from the official Google Chrome package. The proprietary CDM binary
//! is never shipped with this crate; it is located or downloaded at runtime —
//! exactly how Chrome/Brave/Spotify obtain their own copies.

use std::path::{Path, PathBuf};

const SO_NAME: &str = "libwidevinecdm.so";

/// Ensure `dir/libwidevinecdm.so` exists and return its path, installing one if
/// the directory doesn't already have it.
pub fn ensure(dir: &Path) -> anyhow::Result<PathBuf> {
    let target = dir.join(SO_NAME);
    if target.exists() {
        return Ok(target);
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("create CDM dir {}: {e}", dir.display()))?;

    // 1) copy from a CDM already installed by a Chromium-family app.
    if let Some(src) = locate_system_cdm() {
        std::fs::copy(&src, &target)
            .map_err(|e| anyhow::anyhow!("copy CDM from {}: {e}", src.display()))?;
        return Ok(target);
    }

    // 2) download from Google (feature-gated to keep the base crate light).
    #[cfg(feature = "download")]
    {
        download_into(&target)?;
        Ok(target)
    }
    #[cfg(not(feature = "download"))]
    Err(anyhow::anyhow!(
        "no Widevine CDM found on the system and the `download` feature is off — \
         install Chrome/Brave/Chromium, point at a CDM with $WIDEVINE_CDM, or enable `download`"
    ))
}

/// Find an existing `libwidevinecdm.so` from a Chromium-family install. Honours
/// `$WIDEVINE_CDM` (a direct path to the `.so` or a `WidevineCdm` root), then
/// scans Brave/Chrome/Chromium and the Spotify/Discord caches; newest version
/// wins.
pub fn locate_system_cdm() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WIDEVINE_CDM") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
        if let Some(found) = newest_in_root(&p) {
            return Some(found);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let roots = [
        format!("{home}/.config/BraveSoftware/Brave-Browser/WidevineCdm"),
        format!("{home}/.config/google-chrome/WidevineCdm"),
        format!("{home}/.config/chromium/WidevineCdm"),
        format!("{home}/.cache/spotify/WidevineCdm"),
        format!("{home}/.config/discord/WidevineCdm"),
        "/opt/google/chrome/WidevineCdm".to_string(),
    ];
    roots.iter().find_map(|r| newest_in_root(Path::new(r)))
}

/// Within a `WidevineCdm` root (holding `<version>/_platform_specific/...`
/// subdirs), return the `.so` from the highest version present.
fn newest_in_root(root: &Path) -> Option<PathBuf> {
    let mut versions: Vec<PathBuf> = std::fs::read_dir(root).ok()?.filter_map(|e| e.ok().map(|e| e.path())).collect();
    versions.sort();
    versions.into_iter().rev().find_map(|v| {
        let so = v.join("_platform_specific/linux_x64").join(SO_NAME);
        so.exists().then_some(so)
    })
}

/// Download + extract `libwidevinecdm.so` from the official Google Chrome `.deb`
/// (the only stable public source now that the standalone CDM zips are gone and
/// the component endpoint is signature-gated). Writes it to `target`.
#[cfg(feature = "download")]
fn download_into(target: &Path) -> anyhow::Result<()> {
    const DEB_URL: &str =
        "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb";

    // Fetch the .deb fully into memory (one-time, ~130 MB).
    let mut deb = Vec::new();
    std::io::Read::read_to_end(
        &mut ureq::get(DEB_URL).call().map_err(|e| anyhow::anyhow!("download chrome: {e}"))?.into_reader(),
        &mut deb,
    )
    .map_err(|e| anyhow::anyhow!("read chrome .deb: {e}"))?;

    // A .deb is an `ar` archive; pull out the `data.tar.{xz,zst,gz}` member.
    let data = ar_member(&deb, "data.tar")
        .ok_or_else(|| anyhow::anyhow!("no data.tar member in chrome .deb"))?;
    let tar_bytes = decompress(data)?;

    // Find WidevineCdm/.../linux_x64/libwidevinecdm.so inside the tarball.
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    for entry in archive.entries().map_err(|e| anyhow::anyhow!("read data.tar: {e}"))? {
        let mut entry = entry.map_err(|e| anyhow::anyhow!("tar entry: {e}"))?;
        let path = entry.path().map_err(|e| anyhow::anyhow!("tar path: {e}"))?;
        let p = path.to_string_lossy();
        if p.contains("WidevineCdm") && p.ends_with("linux_x64/libwidevinecdm.so") {
            let mut out = std::fs::File::create(target)
                .map_err(|e| anyhow::anyhow!("create {}: {e}", target.display()))?;
            std::io::copy(&mut entry, &mut out).map_err(|e| anyhow::anyhow!("extract CDM: {e}"))?;
            return Ok(());
        }
    }
    anyhow::bail!("libwidevinecdm.so not found inside the chrome .deb")
}

/// Return the contents of the first `ar` member whose name starts with `prefix`.
#[cfg(feature = "download")]
fn ar_member<'a>(ar: &'a [u8], prefix: &str) -> Option<&'a [u8]> {
    let body = ar.strip_prefix(b"!<arch>\n")?;
    let mut off = 0;
    while off + 60 <= body.len() {
        let header = &body[off..off + 60];
        let name = std::str::from_utf8(&header[0..16]).ok()?.trim_end();
        let size: usize = std::str::from_utf8(&header[48..58]).ok()?.trim_end().parse().ok()?;
        let start = off + 60;
        let end = start + size;
        if end > body.len() {
            return None;
        }
        if name.trim_end_matches('/').starts_with(prefix) {
            return Some(&body[start..end]);
        }
        off = end + (size & 1); // members are 2-byte aligned
    }
    None
}

/// Decompress a `data.tar.{xz,zst,gz}` member by sniffing its magic bytes.
#[cfg(feature = "download")]
fn decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    match data {
        [0xFD, b'7', b'z', b'X', b'Z', 0x00, ..] => {
            lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut out)
                .map_err(|e| anyhow::anyhow!("xz decompress: {e}"))?;
        }
        [0x28, 0xB5, 0x2F, 0xFD, ..] => {
            let mut dec = ruzstd::StreamingDecoder::new(std::io::Cursor::new(data))
                .map_err(|e| anyhow::anyhow!("zstd init: {e}"))?;
            std::io::Read::read_to_end(&mut dec, &mut out)
                .map_err(|e| anyhow::anyhow!("zstd decompress: {e}"))?;
        }
        _ => anyhow::bail!("unsupported data.tar compression (magic {:02x?})", &data[..data.len().min(4)]),
    }
    Ok(out)
}

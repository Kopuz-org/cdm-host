//! Sourcing a `libwidevinecdm.so` for [`CdmHost::install_or_open`](crate::CdmHost::install_or_open).
//!
//! Order of preference: a CDM already in the target dir → copy one from an
//! installed Chromium-family app (no network) → (with the `download` feature)
//! fetch it from the official Google Chrome package. The proprietary CDM binary
//! is never shipped with this crate; it is located or downloaded at runtime —
//! exactly how Chrome/Brave/Spotify obtain their own copies.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// The CDM library's file name on this OS.
#[cfg(target_os = "macos")]
const SO_NAME: &str = "libwidevinecdm.dylib";
#[cfg(not(target_os = "macos"))]
const SO_NAME: &str = "libwidevinecdm.so";

/// The `_platform_specific/<dir>` Chromium installs this OS/arch's CDM under,
/// or `None` where it ships no CDM.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const PLATFORM_DIR: Option<&str> = Some("linux_x64");
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const PLATFORM_DIR: Option<&str> = Some("linux_arm64");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const PLATFORM_DIR: Option<&str> = Some("mac_x64");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PLATFORM_DIR: Option<&str> = Some("mac_arm64");
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "macos",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
)))]
const PLATFORM_DIR: Option<&str> = None;

/// Ensure the CDM library (`libwidevinecdm.so`, `.dylib` on macOS) exists in
/// `dir` and return its path, installing one if the directory doesn't already
/// have it. A leading `~` in `dir` is expanded to `$HOME`.
pub fn ensure(dir: &Path) -> Result<PathBuf> {
    let dir = &expand_tilde(dir);
    let target = dir.join(SO_NAME);
    if target.exists() {
        return Ok(target);
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::io(format!("create CDM dir {}", dir.display()), e))?;

    // 1) copy from a CDM already installed by a Chromium-family app.
    if let Some(src) = locate_system_cdm() {
        std::fs::copy(&src, &target)
            .map_err(|e| Error::io(format!("copy CDM from {}", src.display()), e))?;
        return Ok(target);
    }

    // 2) download from Google (feature-gated to keep the base crate light).
    #[cfg(feature = "download")]
    {
        download_into(&target)?;
        Ok(target)
    }
    #[cfg(not(feature = "download"))]
    Err(Error::NoCdmFound)
}

/// Expand a leading `~` (alone or as `~/...`) to `$HOME`. `~user` forms and
/// paths without a leading tilde are returned unchanged, as is everything when
/// `$HOME` is unset.
fn expand_tilde(path: &Path) -> PathBuf {
    expand_tilde_with(path, std::env::var_os("HOME").map(PathBuf::from))
}

fn expand_tilde_with(path: &Path, home: Option<PathBuf>) -> PathBuf {
    let Some(home) = home else {
        return path.to_path_buf();
    };
    match path.strip_prefix("~") {
        Ok(rest) if rest.as_os_str().is_empty() => home,
        Ok(rest) => home.join(rest),
        Err(_) => path.to_path_buf(),
    }
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
    #[cfg(not(target_os = "macos"))]
    let roots = [
        format!("{home}/.config/BraveSoftware/Brave-Browser/WidevineCdm"),
        format!("{home}/.config/google-chrome/WidevineCdm"),
        format!("{home}/.config/chromium/WidevineCdm"),
        format!("{home}/.cache/spotify/WidevineCdm"),
        format!("{home}/.config/discord/WidevineCdm"),
        "/opt/google/chrome/WidevineCdm".to_string(),
    ];
    #[cfg(target_os = "macos")]
    let roots = [
        format!("{home}/Library/Application Support/BraveSoftware/Brave-Browser/WidevineCdm"),
        format!("{home}/Library/Application Support/Google/Chrome/WidevineCdm"),
        format!("{home}/Library/Application Support/Chromium/WidevineCdm"),
    ];
    roots.iter().find_map(|r| newest_in_root(Path::new(r)))
}

/// Within a `WidevineCdm` root (holding `<version>/_platform_specific/...`
/// subdirs), return this platform's CDM from the highest version present.
fn newest_in_root(root: &Path) -> Option<PathBuf> {
    let platform = PLATFORM_DIR?;
    let mut versions: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    sort_versions(&mut versions);
    versions.into_iter().rev().find_map(|v| {
        let so = v.join("_platform_specific").join(platform).join(SO_NAME);
        so.exists().then_some(so)
    })
}

/// Sort version directories ascending by their dotted numeric name, so
/// `4.10.x` ranks above `4.9.x`. Names that are not all-numeric sort first.
fn sort_versions(versions: &mut [PathBuf]) {
    versions.sort_by_cached_key(|p| (version_key(p), p.clone()));
}

fn version_key(path: &Path) -> Option<Vec<u64>> {
    path.file_name()?
        .to_str()?
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

/// Download + extract `libwidevinecdm.so` from the official Google Chrome `.deb`
/// (the only stable public source now that the standalone CDM zips are gone and
/// the component endpoint is signature-gated). Writes it to `target`.
#[cfg(feature = "download")]
fn download_into(target: &Path) -> Result<()> {
    // Google publishes the package for x86_64 Linux only.
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(Error::Package(
            "the Chrome package only carries an x86_64 Linux CDM".into(),
        ));
    }
    const DEB_URL: &str =
        "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb";

    // Fetch the .deb fully into memory (one-time, ~130 MB).
    let mut deb = Vec::new();
    std::io::Read::read_to_end(
        &mut ureq::get(DEB_URL)
            .call()
            .map_err(|e| Error::Download {
                context: "download the Chrome package",
                source: e.into(),
            })?
            .into_reader(),
        &mut deb,
    )
    .map_err(|e| Error::io("read the Chrome package", e))?;

    // A .deb is an `ar` archive; pull out the `data.tar.{xz,zst,gz}` member.
    let data = ar_member(&deb, "data.tar")
        .ok_or_else(|| Error::Package("no data.tar member in the .deb".into()))?;
    let tar_bytes = decompress(data)?;

    // Find WidevineCdm/.../linux_x64/libwidevinecdm.so inside the tarball.
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    for entry in archive
        .entries()
        .map_err(|e| Error::io("read data.tar", e))?
    {
        let mut entry = entry.map_err(|e| Error::io("read a data.tar entry", e))?;
        let path = entry
            .path()
            .map_err(|e| Error::io("read a data.tar entry path", e))?;
        let p = path.to_string_lossy();
        if p.contains("WidevineCdm") && p.ends_with("linux_x64/libwidevinecdm.so") {
            let mut out = std::fs::File::create(target)
                .map_err(|e| Error::io(format!("create {}", target.display()), e))?;
            std::io::copy(&mut entry, &mut out).map_err(|e| Error::io("extract the CDM", e))?;
            return Ok(());
        }
    }
    Err(Error::Package(
        "no libwidevinecdm.so inside the .deb".into(),
    ))
}

/// Return the contents of the first `ar` member whose name starts with `prefix`.
#[cfg(feature = "download")]
fn ar_member<'a>(ar: &'a [u8], prefix: &str) -> Option<&'a [u8]> {
    let body = ar.strip_prefix(b"!<arch>\n")?;
    let mut off = 0;
    while off + 60 <= body.len() {
        let header = &body[off..off + 60];
        let name = std::str::from_utf8(&header[0..16]).ok()?.trim_end();
        let size: usize = std::str::from_utf8(&header[48..58])
            .ok()?
            .trim_end()
            .parse()
            .ok()?;
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
fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match data {
        [0xFD, b'7', b'z', b'X', b'Z', 0x00, ..] => {
            lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut out).map_err(|e| {
                Error::Download {
                    context: "xz-decompress data.tar",
                    source: e.into(),
                }
            })?;
        }
        [0x28, 0xB5, 0x2F, 0xFD, ..] => {
            let mut dec =
                ruzstd::StreamingDecoder::new(std::io::Cursor::new(data)).map_err(|e| {
                    Error::Download {
                        context: "start zstd-decompressing data.tar",
                        source: e.into(),
                    }
                })?;
            std::io::Read::read_to_end(&mut dec, &mut out)
                .map_err(|e| Error::io("zstd-decompress data.tar", e))?;
        }
        _ => {
            return Err(Error::Package(format!(
                "unsupported data.tar compression (magic {:02x?})",
                &data[..data.len().min(4)]
            )))
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Option<PathBuf> {
        Some(PathBuf::from("/home/u"))
    }

    #[test]
    fn tilde_alone_is_home() {
        assert_eq!(
            expand_tilde_with(Path::new("~"), home()),
            Path::new("/home/u")
        );
    }

    #[test]
    fn tilde_slash_joins_home() {
        assert_eq!(
            expand_tilde_with(Path::new("~/.local/share/cdm"), home()),
            Path::new("/home/u/.local/share/cdm")
        );
    }

    #[test]
    fn other_paths_are_unchanged() {
        for p in ["~user/cdm", "/opt/~/cdm", "cdm/~", "./~"] {
            assert_eq!(expand_tilde_with(Path::new(p), home()), Path::new(p));
        }
    }

    #[test]
    fn tilde_without_home_is_unchanged() {
        assert_eq!(
            expand_tilde_with(Path::new("~/cdm"), None),
            Path::new("~/cdm")
        );
    }

    #[test]
    fn versions_sort_numerically() {
        let mut v: Vec<PathBuf> = ["4.10.2830.0", "4.9.0.0", "4.10.1679.0", "10.0.0.0"]
            .iter()
            .map(|n| Path::new("/root").join(n))
            .collect();
        sort_versions(&mut v);
        let names: Vec<_> = v.iter().map(|p| p.file_name().unwrap()).collect();
        assert_eq!(names, ["4.9.0.0", "4.10.1679.0", "4.10.2830.0", "10.0.0.0"]);
    }

    #[test]
    fn non_version_dirs_sort_first() {
        let mut v = vec![PathBuf::from("/r/4.10.0.0"), PathBuf::from("/r/latest")];
        sort_versions(&mut v);
        assert_eq!(
            v,
            [PathBuf::from("/r/latest"), PathBuf::from("/r/4.10.0.0")]
        );
        assert_eq!(version_key(Path::new("/r/4.x.0")), None);
        assert_eq!(version_key(Path::new("/r/4.10.2")), Some(vec![4, 10, 2]));
    }

    #[test]
    fn newest_in_missing_root_is_none() {
        assert_eq!(newest_in_root(Path::new("/nonexistent/WidevineCdm")), None);
    }

    /// Build a GNU `ar` archive from `(name, contents)` members.
    #[cfg(feature = "download")]
    fn ar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            let header = format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                format!("{name}/"),
                0,
                0,
                0,
                100644,
                data.len()
            );
            assert_eq!(header.len(), 60);
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    #[cfg(feature = "download")]
    #[test]
    fn ar_member_finds_by_prefix_past_odd_padding() {
        let deb = ar(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", b"odd"),
            ("data.tar.xz", b"payload"),
        ]);
        assert_eq!(ar_member(&deb, "data.tar"), Some(&b"payload"[..]));
        assert_eq!(ar_member(&deb, "control.tar"), Some(&b"odd"[..]));
    }

    #[cfg(feature = "download")]
    #[test]
    fn ar_member_rejects_bad_input() {
        let deb = ar(&[("debian-binary", b"2.0\n")]);
        assert_eq!(ar_member(&deb, "data.tar"), None);
        assert_eq!(ar_member(b"not an archive", "data.tar"), None);

        let mut truncated = ar(&[("data.tar.xz", b"payload")]);
        truncated.truncate(truncated.len() - 2);
        assert_eq!(ar_member(&truncated, "data.tar"), None);
    }
}

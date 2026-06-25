# cdm-host

A native Rust host for the system **Widevine CDM** (`libwidevinecdm.so`). It
loads the CDM that ships with Chrome/Brave (or any Chromium-family app) and
drives it through its official `cdm::ContentDecryptionModule` interface to:

* generate a license **challenge**,
* accept a license **response** (loading the content keys), and
* **decrypt** CENC buffers.

No keys are extracted — the CDM keeps its device key sealed and does the work
internally, exactly as a browser does. This is service-agnostic: any Widevine
service (Spotify web, Apple Music web, …) is just a thin auth + manifest layer
on top.

## Usage

```rust
use cdm_host::CdmHost;

// Either point at a CDM yourself…
let cdm = CdmHost::open("/path/to/libwidevinecdm.so")?;

// …or have one ensured under a directory you choose (copied from an installed
// browser, or — with the `download` feature — fetched from Google):
let cdm = CdmHost::install_or_open("~/.cache/myapp/widevine")?;

let challenge = cdm.challenge(&pssh_box)?;   // → send to the license server
cdm.update(&license_response)?;              // ← keys loaded
let clear = cdm.decrypt(&sample, &kid, &iv, &subsamples)?;
```

## The CDM binary is never shipped

`libwidevinecdm.so` is Google's proprietary, non-redistributable binary, so this
crate doesn't bundle it. [`vendor`] sources it at runtime the same way
Chrome/Brave/Spotify do — by locating an existing copy, or downloading one:

* [`CdmHost::open`] — you supply the path.
* [`CdmHost::install_or_open`] — ensure it under your dir: existing copy → copy
  from a detected local CDM (Brave/Chrome/Chromium/Spotify/Discord) → (feature
  `download`) extract it from the official Google Chrome package.

## Build — no C++ compiler needed on supported targets

`shim.cc` implements `cdm::Host_11` (compiled against the vendored Chromium
`content_decryption_module.h`, so the vtable is correct-by-construction).
`build.rs` **links a prebuilt static `shim` (`prebuilt/<target>/libcdmshim.a`)
when one is shipped for the target — no compiler required** (only the ubiquitous
`libstdc++` runtime). Targets without a prebuilt fall back to compiling `shim.cc`
via `cc`, which needs `g++`/`clang++`.

* prebuilt target → no compiler, `.h`/`.cc` unused.
* other target → needs a C++ compiler + the vendored header (BSD, from
  `chromium.googlesource.com/chromium/cdm`).

Regenerate a prebuilt:

```sh
g++ -std=c++14 -fPIC -Ivendor -c shim.cc -o shim.o
ar rcs prebuilt/<target-triple>/libcdmshim.a shim.o
```

## Cargo features

* `download` — enable the Google-Chrome-package fallback in `install_or_open`
  (pulls `ureq` + pure-Rust `lzma-rs`/`ruzstd`/`tar` for extraction). Off by
  default to keep the base crate light.

## Standalone

This crate has no Spotify (or any service) code; it's consumed as a git/crates.io
dependency.

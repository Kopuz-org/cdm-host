# cdm-host

A native Rust host for the system **Widevine CDM** (`libwidevinecdm.so`). It
loads the CDM that ships with Chrome/Brave and drives it through its official
`cdm::ContentDecryptionModule` interface to:

* generate a license **challenge**,
* accept a license **response** (loading the content keys), and
* **decrypt** CENC buffers.

No keys are extracted — the CDM keeps its device key sealed and does the work
internally, exactly as a browser does. This is service-agnostic: any Widevine
service (Spotify web, Apple Music web, …) is just a thin auth + manifest layer
on top.

## How it works

`shim.cc` implements `cdm::Host_11` (compiled against the vendored Chromium
`content_decryption_module.h`, so the vtable is correct-by-construction) and
exposes a small C API; `src/lib.rs` is the safe Rust wrapper.

```rust
cdm_host::open("/path/to/libwidevinecdm.so")?;
let challenge = cdm_host::challenge(&pssh_box)?;   // → send to the license server
cdm_host::update(&license_response)?;              // ← keys loaded
let clear = cdm_host::decrypt(&sample, &kid, &iv, &subsamples)?;
```

## Build requirements

* a C++ compiler (`g++`/`clang++`) — `build.rs` compiles `shim.cc` via `cc`
* `libwidevinecdm.so` present at runtime (bundled with Chrome/Brave)
* the vendored CDM API header in `vendor/` (BSD, from `chromium.googlesource.com/chromium/cdm`)

## Standalone

This crate has no Spotify (or any service) code and is meant to live in its own
repo, consumed as a git dependency.

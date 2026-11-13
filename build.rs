use std::path::Path;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let dir = Path::new("prebuilt").join(&target);
    let prebuilt = dir.join("libcdmshim.a");

    if prebuilt.exists() {
        // Link the shipped prebuilt shim — no C++ compiler required on this host.
        println!("cargo:rustc-link-search=native={}", dir.display());
        println!("cargo:rustc-link-lib=static=cdmshim");
        // The shim needs the C++ runtime (std::vector/string/chrono), which is
        // present on essentially every system even without a compiler: libc++
        // on Apple and the BSDs, libstdc++ elsewhere.
        let cxx = match target_os.as_str() {
            "macos" | "ios" | "freebsd" | "openbsd" => "c++",
            _ => "stdc++",
        };
        println!("cargo:rustc-link-lib=dylib={cxx}");
    } else {
        // No prebuilt for this target → compile the shim (needs g++/clang++).
        // cc links the matching C++ runtime itself.
        cc::Build::new()
            .cpp(true)
            .file("shim.cc")
            .include("vendor")
            .flag_if_supported("-std=c++14")
            .flag_if_supported("-Wno-unused-parameter")
            .compile("cdmshim");
    }

    // dlopen/dlsym live in libdl on Linux; elsewhere they are in libc.
    if target_os == "linux" {
        println!("cargo:rustc-link-lib=dylib=dl");
    }
    println!("cargo:rerun-if-changed=shim.cc");
    println!("cargo:rerun-if-changed=vendor/content_decryption_module.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=prebuilt");
}

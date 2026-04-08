fn main() {
    #[cfg(feature = "simd")]
    {
        let libgm_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../libgraphmatch");
        let src_dir = libgm_dir.join("src");
        let include_dir = libgm_dir.join("include");

        // Rerun if C++ sources change
        println!("cargo:rerun-if-changed={}", src_dir.display());
        println!("cargo:rerun-if-changed={}", include_dir.display());

        // Always compile from source via cc crate for maximum ABI compatibility.
        // The cc crate uses the same compiler as the Rust toolchain (MSVC or GCC).

        let sources = [
            "simd_intersect.cpp",
            "csr_graph.cpp",
            "pattern.cpp",
            "pruning.cpp",
            "matcher.cpp",
            "scorer.cpp",
            "result.cpp",
            "graphmatch_cabi.cpp",
        ];

        let mut build = cc::Build::new();
        build
            .cpp(true)
            .std("c++20")
            .opt_level(3)
            .include(&include_dir);

        let compiler = build.get_compiler();
        if compiler.is_like_msvc() {
            build.flag("/arch:AVX2");
            build.flag("/EHs-c-");
            build.flag("/GR-");
        } else {
            build.flag("-fno-exceptions");
            build.flag("-fno-rtti");
            build.flag("-march=native");
            build.flag("-Wall");
            build.flag("-Wextra");
        }

        for src in &sources {
            build.file(src_dir.join(src));
        }

        build.compile("graphmatch");

        if !compiler.is_like_msvc() {
            if compiler.is_like_clang() {
                println!("cargo:rustc-link-lib=c++");
            } else {
                println!("cargo:rustc-link-lib=stdc++");
            }
        }
    }
}

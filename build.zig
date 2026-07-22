const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const bedrock_c_mul_base = b.option(bool, "bedrock-c-mul-base", "Link Bedrock C P-256 mul_base") orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "bedrock_c_mul_base", bedrock_c_mul_base);

    // Main TLS module
    const tls_module = b.addModule("tls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tls_module.addOptions("build_options", build_options);
    addHwCryptoAsm(b, tls_module, target);

    // Unit tests
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addOptions("build_options", build_options);
    addHwCryptoAsm(b, lib_mod, target);
    const unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    addBedrockCMulBase(b, unit_tests, bedrock_c_mul_base);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Benchmarks (rustls-style handshake + bulk transfer)
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("tls", tls_module);
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });
    addBedrockCMulBase(b, bench_exe, bedrock_c_mul_base);
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run TLS benchmarks");
    bench_step.dependOn(&run_bench.step);

    const certs_mod = b.createModule(.{
        .root_source_file = b.path("bench/certs.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tls_server_mod = b.createModule(.{
        .root_source_file = b.path("examples/tls_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    tls_server_mod.addImport("tls", tls_module);
    tls_server_mod.addImport("certs", certs_mod);
    const tls_server_exe = b.addExecutable(.{
        .name = "tls-server",
        .root_module = tls_server_mod,
    });
    tls_server_exe.root_module.link_libc = true;
    addBedrockCMulBase(b, tls_server_exe, bedrock_c_mul_base);
    b.installArtifact(tls_server_exe);
    const run_tls_server = b.addRunArtifact(tls_server_exe);
    const tls_server_args = b.option(
        []const []const u8,
        "tls-server-arg",
        "Argument passed to tls-server; repeat the option for multiple arguments",
    ) orelse &.{};
    run_tls_server.addArgs(tls_server_args);
    const tls_server_step = b.step("tls-server", "Run TLS 1.3 echo server (default :8443)");
    tls_server_step.dependOn(&run_tls_server.step);

    // Fuzz targets (libFuzzer-compatible when built with -Dfuzz)
    const fuzz = b.option(bool, "fuzz", "Build fuzz targets") orelse false;
    if (fuzz) {
        const record_fuzz_mod = b.createModule(.{
            .root_source_file = b.path("fuzz/record_fuzz.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        });
        record_fuzz_mod.addImport("tls", tls_module);
        const record_fuzz = b.addExecutable(.{
            .name = "fuzz-record",
            .root_module = record_fuzz_mod,
        });
        record_fuzz.root_module.stack_protector = false;
        record_fuzz.root_module.link_libc = true;

        const handshake_fuzz_mod = b.createModule(.{
            .root_source_file = b.path("fuzz/handshake_fuzz.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        });
        handshake_fuzz_mod.addImport("tls", tls_module);
        const handshake_fuzz = b.addExecutable(.{
            .name = "fuzz-handshake",
            .root_module = handshake_fuzz_mod,
        });
        handshake_fuzz.root_module.stack_protector = false;
        handshake_fuzz.root_module.link_libc = true;
        b.installArtifact(handshake_fuzz);

        const fuzz_step = b.step("fuzz", "Build fuzz targets");
        fuzz_step.dependOn(&b.addInstallArtifact(record_fuzz, .{}).step);
        fuzz_step.dependOn(&b.addInstallArtifact(handshake_fuzz, .{}).step);
    }
}

fn addBedrockCMulBase(b: *std.Build, compile: *std.Build.Step.Compile, enabled: bool) void {
    if (!enabled) return;
    compile.root_module.link_libc = true;
    compile.root_module.addIncludePath(b.path("src/crypto/c/bedrock"));
    compile.root_module.addCSourceFile(.{
        .file = b.path("src/crypto/c/bedrock/bedrock_mul_base.c"),
        .flags = &.{ "-std=c11", "-O3" },
    });
    compile.root_module.addCSourceFile(.{
        .file = b.path("src/crypto/c/bedrock/bedrock_double_base_verify.c"),
        .flags = &.{ "-std=c11", "-O3" },
    });
    compile.root_module.addCSourceFile(.{
        .file = b.path("src/crypto/c/bedrock/bedrock_point_mul_public.c"),
        .flags = &.{ "-std=c11", "-O3" },
    });
}

fn addHwCryptoAsm(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    const arch = target.result.cpu.arch;
    const os = target.result.os.tag;

    if (arch == .aarch64 and (os == .macos or os == .linux)) {
        const suffix = if (os == .macos) "apple" else "linux";
        module.addIncludePath(b.path("src/crypto/aarch64/include"));
        inline for (.{
            "aesv8-gcm-armv8",
            "ghashv8-armv8",
            "aesv8-armv8",
            "p256-armv8-asm",
        }) |base| {
            const path = b.fmt("src/crypto/aarch64/{s}-{s}.S", .{ base, suffix });
            module.addAssemblyFile(b.path(path));
        }
        return;
    }

    if (arch == .x86_64 and (os == .macos or os == .linux)) {
        const suffix = if (os == .macos) "apple" else "linux";
        module.addIncludePath(b.path("src/crypto/x86_64/include"));
        inline for (.{
            "aes-gcm-avx2-x86_64",
            "aesni-x86_64",
            "p256-x86_64-asm",
        }) |base| {
            const path = b.fmt("src/crypto/x86_64/{s}-{s}.S", .{ base, suffix });
            module.addAssemblyFile(b.path(path));
        }
        inline for (.{
            "fiat_p256_adx_mul",
            "fiat_p256_adx_sqr",
        }) |base| {
            module.addAssemblyFile(b.path(b.fmt("src/crypto/x86_64/{s}.S", .{base})));
        }
    }
}

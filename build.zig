const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main TLS module
    const tls_module = b.addModule("tls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addHwGcmAsm(b, tls_module, target);

    // Unit tests
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addHwGcmAsm(b, lib_mod, target);
    const unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
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
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run TLS benchmarks");
    bench_step.dependOn(&run_bench.step);

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

fn addHwGcmAsm(b: *std.Build, module: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    const arch = target.result.cpu.arch;
    const os = target.result.os.tag;

    if (arch == .aarch64 and (os == .macos or os == .linux)) {
        const suffix = if (os == .macos) "apple" else "linux";
        module.addIncludePath(b.path("src/crypto/aarch64/include"));
        inline for (.{
            "aesv8-gcm-armv8",
            "ghashv8-armv8",
            "aesv8-armv8",
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
        }) |base| {
            const path = b.fmt("src/crypto/x86_64/{s}-{s}.S", .{ base, suffix });
            module.addAssemblyFile(b.path(path));
        }
    }
}

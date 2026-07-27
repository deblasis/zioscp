const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // SSH transport backend: "ssh" (default) drives a system ssh subprocess;
    // "libssh2" links libssh2 for a self-contained binary (no ssh dependency).
    const backend = b.option(enum { ssh, libssh2 }, "backend", "SSH transport backend") orelse .ssh;

    // Fleet dependencies (published tarballs).
    const ziocrypt_mod = b.dependency("ziocrypt", .{
        .target = target,
        .optimize = optimize,
    }).module("ziocrypt");
    const ziojson_mod = b.dependency("ziojson", .{
        .target = target,
        .optimize = optimize,
    }).module("ziojson");
    const zioprogress_mod = b.dependency("zioprogress", .{
        .target = target,
        .optimize = optimize,
    }).module("zioprogress");
    const ziorate_mod = b.dependency("ziorate", .{
        .target = target,
        .optimize = optimize,
    }).module("ziorate");
    const zioarg_mod = b.dependency("zioarg", .{
        .target = target,
        .optimize = optimize,
    }).module("zioarg");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("ziocrypt", ziocrypt_mod);
    exe_mod.addImport("ziojson", ziojson_mod);
    exe_mod.addImport("zioprogress", zioprogress_mod);
    exe_mod.addImport("ziorate", ziorate_mod);
    exe_mod.addImport("zioarg", zioarg_mod);

    // Expose the backend choice to the source as a comptime value.
    const build_opts = b.addOptions();
    build_opts.addOption(@TypeOf(backend), "backend", backend);
    exe_mod.addOptions("config", build_opts);

    const exe = b.addExecutable(.{
        .name = "zioscp",
        .root_module = exe_mod,
    });
    if (backend == .libssh2) {
        // Homebrew (Apple Silicon) puts libssh2.dylib here; pkg-config lookup is
        // unreliable from the zig build, so point at it directly. Vendoring the
        // source (slice 2) removes this system dependency.
        exe_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        exe_mod.linkSystemLibrary("ssh2", .{}); // -lssh2; implies libc
    }
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zioscp");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("ziocrypt", ziocrypt_mod);
    test_mod.addImport("ziojson", ziojson_mod);
    test_mod.addImport("zioprogress", zioprogress_mod);
    test_mod.addImport("ziorate", ziorate_mod);
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Integration test: round-trips against a real sshd sftp-server (needs the
    // Docker harness in tests/sftp-integration.sh). Separate step so `zig build
    // test` stays fast and network-free.
    const integ_mod = b.createModule(.{
        .root_source_file = b.path("src/integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    integ_mod.addImport("ziocrypt", ziocrypt_mod);
    integ_mod.addImport("ziojson", ziojson_mod);
    integ_mod.addImport("zioprogress", zioprogress_mod);
    integ_mod.addImport("ziorate", ziorate_mod);
    const integ_tests = b.addTest(.{ .root_module = integ_mod });
    const run_integ = b.addRunArtifact(integ_tests);
    const integ_step = b.step("integration", "Run integration tests (needs the Docker sftp harness)");
    integ_step.dependOn(&run_integ.step);
}

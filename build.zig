const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // SSH transport backend: "ssh" drives a system ssh subprocess; "libssh2"
    // links libssh2 for a self-contained binary (no ssh dependency).
    // Default is libssh2 on Windows and ssh elsewhere. The ssh-subprocess
    // backend relies on driving `ssh -s sftp` over its piped stdio, which does
    // not work on Windows: std.Io's subprocess pipes are overlapped named pipes
    // that readStreaming returns EOF on before data arrives, and Windows
    // ssh.exe does not serve a usable SFTP stream over `-s sftp` pipes. The
    // libssh2 backend (which builds its own winsock socket on Windows) is the
    // working, self-contained option there.
    const default_backend: enum { ssh, libssh2 } =
        if (target.result.os.tag == .windows) .libssh2 else .ssh;
    const Backend = @TypeOf(default_backend);
    const backend = b.option(Backend, "backend", "SSH transport backend") orelse default_backend;

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
        // Self-contained libssh2 backend: link the static, zig-cc-built libssh2
        // (openssl backend) + OpenSSL, so the binary needs no libssh2/openssl
        // dylib (only system frameworks + libc, + libz for compression). The C
        // libraries are built by tools/vendor-libssh2.sh into vendor/<os>-<arch>/.
        // The `vendor-libssh2` step runs that script (an idempotent no-op once
        // built); the exe depends on it so the libs exist before linking.
        const ti = target.result;
        const ossl_target: ?[]const u8 = switch (ti.os.tag) {
            .macos => switch (ti.cpu.arch) {
                .aarch64 => "darwin64-arm64-cc",
                .x86_64 => "darwin64-x86_64-cc",
                else => null,
            },
            .linux => switch (ti.cpu.arch) {
                .x86_64 => "linux-x86_64",
                .aarch64 => "linux-aarch64",
                else => null,
            },
            .windows => switch (ti.cpu.arch) {
                .x86_64 => "mingw64", // mingw-w64 via zig cc (x86_64-windows-gnu)
                else => null,
            },
            else => null,
        };
        if (ossl_target == null) {
            std.debug.print("error: libssh2 vendor has no OpenSSL Configure target for {s}-{s}\n", .{ @tagName(ti.os.tag), @tagName(ti.cpu.arch) });
        }
        const vendor_name = std.fmt.allocPrint(b.allocator, "{s}-{s}", .{ @tagName(ti.os.tag), @tagName(ti.cpu.arch) }) catch @panic("OOM");
        const zig_triple = std.fmt.allocPrint(b.allocator, "{s}-{s}", .{
            @tagName(ti.cpu.arch),
            switch (ti.os.tag) {
                .macos => "macos",
                .linux => "linux-gnu",
                .windows => "windows-gnu",
                else => "none",
            },
        }) catch @panic("OOM");

        const vendor_run = b.addSystemCommand(&.{
            "tools/vendor-libssh2.sh",
            vendor_name,
            ossl_target orelse "unsupported",
            zig_triple,
        });
        const vendor_step = b.step("vendor-libssh2", "Build vendored libssh2+openssl into vendor/<name>/ (used by -Dbackend=libssh2)");
        vendor_step.dependOn(&vendor_run.step);

        const p_ssh2 = std.fmt.allocPrint(b.allocator, "vendor/{s}/lib/libssh2.a", .{vendor_name}) catch @panic("OOM");
        const p_ssl = std.fmt.allocPrint(b.allocator, "vendor/{s}/lib/libssl.a", .{vendor_name}) catch @panic("OOM");
        const p_crypto = std.fmt.allocPrint(b.allocator, "vendor/{s}/lib/libcrypto.a", .{vendor_name}) catch @panic("OOM");
        exe_mod.addObjectFile(b.path(p_ssh2));
        exe_mod.addObjectFile(b.path(p_ssl));
        exe_mod.addObjectFile(b.path(p_crypto));
        exe_mod.linkSystemLibrary("c", .{}); // libc (extern "c" fns; sets link_libc)
        exe.step.dependOn(&vendor_run.step); // ensure the C libs are built before linking
        switch (ti.os.tag) {
            .macos => {
                exe_mod.linkFramework("Security", .{});
                exe_mod.linkFramework("CoreFoundation", .{});
            },
            .windows => {
                // mingw system libs that OpenSSL/libssh2 pull in on Windows.
                exe_mod.linkSystemLibrary("ws2_32", .{}); // winsock (libssh2 sockets)
                exe_mod.linkSystemLibrary("advapi32", .{}); // crypto/syscalls
                exe_mod.linkSystemLibrary("crypt32", .{}); // cert store
                exe_mod.linkSystemLibrary("bcrypt", .{}); // RNG
                exe_mod.linkSystemLibrary("gdi32", .{});
            },
            else => {},
        }
        // No -lz: the vendor script builds libssh2 without zlib (--without-libz-prefix)
        // and OpenSSL with no-comp, so neither references deflate/inflate.
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

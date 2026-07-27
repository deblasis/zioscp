const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module
    const mod = b.addModule("ziojson", .{
        .root_source_file = b.path("src/ziojson.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Tests
    const unit_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Example
    const example_mod = b.createModule(.{
        .root_source_file = b.path("examples/example.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ziojson", .module = mod }},
    });
    const example_exe = b.addExecutable(.{
        .name = "ziojson-example",
        .root_module = example_mod,
    });
    const run_example = b.addRunArtifact(example_exe);
    if (b.args) |args| run_example.addArgs(args);
    const run_example_step = b.step("run-example", "Run the example");
    run_example_step.dependOn(&run_example.step);
}

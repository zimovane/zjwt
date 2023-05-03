const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const build_step = b.addExecutable(.{ .name = "zjwt", .root_source_file = .{ .path = "src/main.zig" } });
    b.installArtifact(build_step);
    _ = b.addRunArtifact(build_step);
}

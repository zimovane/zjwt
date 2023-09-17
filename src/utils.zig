const std = @import("std");
const testing = std.testing;
const fmt = std.fmt;

pub fn hexToBytes(comptime expected_hex: []const u8) []const u8 {
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    for (&expected_bytes, 0..) |*r, i| {
        r.* = fmt.parseInt(u8, expected_hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }
    return &expected_bytes;
}

// Hash using the specified hasher `H` asserting `expected == H(input)`.
pub fn assertEqualHash(comptime Hasher: anytype, comptime expected_hex: *const [Hasher.digest_length * 2:0]u8, input: []const u8) !void {
    var h: [Hasher.digest_length]u8 = undefined;
    Hasher.hash(input, &h, .{});

    try assertEqual(expected_hex, &h);
}

// Assert `expected` == hex(`input`) where `input` is a bytestring
pub fn assertEqual(comptime expected_hex: []const u8, input: []const u8) !void {
    const expected_bytes = hexToBytes(expected_hex);
    try testing.expectEqualSlices(u8, expected_bytes, input);
}

pub fn equalSlices(expected_hex: []const u8, input: []const u8) bool {
    if (expected_hex.ptr == input.ptr and expected_hex.len == input.len) {
        return true;
    }
    const shortest = @min(expected_hex.len, input.len);
    var index: usize = 0;
    while (index < shortest) : (index += 1) {
        if (!std.meta.eql(input[index], expected_hex[index])) return false;
    }
    return true;
}

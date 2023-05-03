const std = @import("std");
const testing = std.testing;
const fmt = std.fmt;

pub fn compareSlices(comptime T: type, expected: []const T, actual: []const T) bool {
    if (expected.len != actual.len) return false;
    if (expected.ptr == actual.ptr) return true;
    const len = expected.len;
    var index: usize = 0;
    while (index < len) : (index += 1) {
        if (!std.meta.eql(actual[index], expected[index])) break;
    }
    return index == len - 1;
}

// Hash using the specified hasher `H` asserting `expected == H(input)`.
pub fn assertEqualHash(comptime Hasher: anytype, comptime expected_hex: *const [Hasher.digest_length * 2:0]u8, input: []const u8) !void {
    var h: [Hasher.digest_length]u8 = undefined;
    Hasher.hash(input, &h, .{});

    try assertEqual(expected_hex, &h);
}

// Assert `expected` == hex(`input`) where `input` is a bytestring
pub fn assertEqual(comptime expected_hex: [:0]const u8, input: []const u8) !void {
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    for (&expected_bytes, 0..) |*r, i| {
        r.* = fmt.parseInt(u8, expected_hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }

    try testing.expectEqualSlices(u8, &expected_bytes, input);
}

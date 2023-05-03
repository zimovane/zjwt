const std = @import("std");

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

const std = @import("std");
const win = @import("win");
const time = std.time;
const builtin = @import("builtin");

// Compile-time seed using build timestamp
fn RandomCompileTimeSeed() u32 {
    const timestamp_str = @embedFile("timestamp.txt");
    var sum: u32 = 0;
    for (timestamp_str) |c| {
        sum = sum *% 31 +% c;
    }
    return sum;
}

const g_KEY: u32 = RandomCompileTimeSeed() % 0xFF;
const SEED: u5 = 5;

// implement compile time hashing algorithms
// djb2 wide
fn HashStringDjb2W(comptime String: [*:0]const u16) u32 {
    var Hash: u32 = g_KEY;
    var i: usize = 0;
    while (String[i] != 0) : (i += 1) {
        Hash = @as(u32, @truncate((@as(u64, Hash) << SEED) +
            @as(u64, Hash) +
            @as(u64, String[i])));
    }
    return Hash;
}

// djb2 ascii
fn HashStringDjb2A(comptime String: [*:0]const u8) u32 {
    var Hash: u32 = g_KEY;
    var i: usize = 0;
    while (String[i] != 0) : (i += 1) {
        Hash = @as(u32, @truncate((@as(u64, Hash) << SEED) +
            @as(u64, Hash) +
            @as(u64, String[i])));
    }
    return Hash;
}

pub fn main() !void {
    const ascii_hash = HashStringDjb2A("Hello, World!");
    std.debug.print("ASCII Hash: {x}\n", .{ascii_hash});

    // Example wide string
    const wide_str = [_:0]u16{ 'H', 'e', 'l', 'l', 'o' };
    const wide_hash = HashStringDjb2W(&wide_str);
    std.debug.print("Wide Hash: {x}\n", .{wide_hash});
}

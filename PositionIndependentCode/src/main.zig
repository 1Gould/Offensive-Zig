// Pre-computed hashes at compile time
const ASCII_HASH = HashStringDjb2A("Hello");

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

pub export fn shellcode_entry() callconv(.C) void {
    _ = ASCII_HASH;
    while (true) {}
}

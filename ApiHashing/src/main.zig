const std = @import("std");
const unicode = std.unicode;
const win = std.os.windows;

// Windows types
const PVOID = win.PVOID;
const ULONG = win.ULONG;
const LIST_ENTRY = win.LIST_ENTRY;
const UNICODE_STRING = win.UNICODE_STRING;
const HANDLE = win.HANDLE;

// Windows structures
pub const PEB = extern struct {
    Reserved1: [2]u8,
    BeingDebugged: u8,
    Reserved2: [1]u8,
    Reserved3: [2]?*anyopaque,
    Ldr: ?*PEB_LDR_DATA,
    ProcessParameters: ?*RTL_USER_PROCESS_PARAMETERS,
    Reserved4: [3]?*anyopaque,
    AtlThunkSListPtr: ?*anyopaque,
    Reserved5: ?*anyopaque,
    Reserved6: u32,
    Reserved7: ?*anyopaque,
    Reserved8: u32,
    AtlThunkSListPtr32: u32,
    Reserved9: [45]?*anyopaque,
    Reserved10: [96]u8,
    PostProcessInitRoutine: ?*anyopaque,
    Reserved11: [128]u8,
    Reserved12: [1]?*anyopaque,
    SessionId: u32,
};

pub const TEB = extern struct {
    Reserved1: [12]?*anyopaque,
    ProcessEnvironmentBlock: ?*PEB,
    Reserved2: [399]?*anyopaque,
    Reserved3: [1952]u8,
    TlsSlots: [64]?*anyopaque,
    Reserved4: [8]u8,
    Reserved5: [26]?*anyopaque,
    ReservedForOle: ?*anyopaque,
    Reserved6: [4]?*anyopaque,
    TlsExpansionSlots: ?*anyopaque,
};

pub const PEB_LDR_DATA = extern struct {
    Reserved1: [8]u8,
    Reserved2: [3]?*anyopaque,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    EntryInProgress: ?*anyopaque,
    ShutdownInProgress: u8,
    ShutdownThreadId: HANDLE,
};

pub const RTL_USER_PROCESS_PARAMETERS = extern struct {
    Reserved1: [16]u8,
    Reserved2: [10]?*anyopaque,
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    DllBase: ?*anyopaque,
    EntryPoint: ?*anyopaque,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: u32,
    LoadCount: u16,
    TlsIndex: u16,
    HashLinks: LIST_ENTRY,
    TimeDateStamp: u32,
};

// Pre-computed hashes at compile time
const ASCII_HASH = HashStringDjb2A("kernel32.dll", g_KEY);
const WIDE_HASH = HashStringDjb2Utf8ToUtf16("kernel32.dll", g_KEY);
const g_KEY: u32 = RandomCompileTimeSeed() % 0xFF;
const SEED: u5 = 5;

// Compile-time seed using build timestamp
fn RandomCompileTimeSeed() u32 {
    const timestamp_str = @embedFile("timestamp.txt");
    var sum: u32 = 0;
    for (timestamp_str) |c| {
        sum = sum *% 31 +% c;
    }
    return sum;
}

fn GetPEB() *PEB {
    return asm volatile (
        \\ movq %%gs:0x60, %[result]
        : [result] "=r" (-> *PEB),
    );
}

fn GetTEB() *TEB {
    return asm volatile (
        \\ movq %%gs:0x30, %[result]
        : [result] "=r" (-> *TEB),
    );
}

// implement compile time hashing algorithms
// djb2 wide
fn HashStringDjb2W(String: [*:0]const u16, key: u32) u32 {
    var Hash: u32 = key;
    var i: usize = 0;
    while (String[i] != 0) : (i += 1) {
        Hash = @as(u32, @truncate((@as(u64, Hash) << SEED) +
            @as(u64, Hash) +
            @as(u64, String[i])));
    }
    return Hash;
}

// djb2 ascii
fn HashStringDjb2A(String: [*:0]const u8, key: u32) u32 {
    var Hash: u32 = key;
    var i: usize = 0;
    while (String[i] != 0) : (i += 1) {
        Hash = @as(u32, @truncate((@as(u64, Hash) << SEED) +
            @as(u64, Hash) +
            @as(u64, String[i])));
    }
    return Hash;
}

fn HashString(s: []const u8) u64 {
    var hash: u64 = 5381;
    for (s) |c| {
        // We must use @addWithOverflow and @shlWithOverflow, as Zig would declare comptime error because of the overflow
        // The builtins return tuples with two values - the result in [0] and overflow bit in [1]
        hash = @addWithOverflow(@shlWithOverflow(hash, 5)[0], hash + std.ascii.toUpper(c))[0];
    }
    return hash;
}

// djb2 utf8 to utf16
fn HashStringDjb2Utf8ToUtf16(comptime String: []const u8, key: u32) u32 {
    @setEvalBranchQuota(100_000_000);
    comptime {
        var Hash: u32 = key;
        const wide_str = std.unicode.utf8ToUtf16LeStringLiteral(String);
        for (wide_str) |c| {
            Hash = @as(u32, @truncate((@as(u64, Hash) << SEED) +
                @as(u64, Hash) +
                @as(u64, c)));
        }
        return Hash;
    }
}

pub fn GetModuleName(module_name: []const u16) ?*anyopaque {
    const peb = GetPEB();
    const ldr = peb.Ldr;
    var curr_module = @as(*LDR_DATA_TABLE_ENTRY, @ptrCast(@alignCast(ldr.InLoadOrderModuleList.Flink)));

    std.debug.print("\n[+] Starting module search\n", .{});

    while (curr_module.DllBase != null) {
        const buffer_ptr = @as(?[*]u16, @ptrCast(curr_module.BaseDllName.Buffer));
        if (buffer_ptr == null) {
            curr_module = @as(*LDR_DATA_TABLE_ENTRY, @ptrCast(@alignCast(curr_module.InLoadOrderModuleList.Flink)));
            continue;
        }

        const curr_name = curr_module.BaseDllName.Buffer[0 .. curr_module.BaseDllName.Length / 2];

        // Convert module name to UTF-8 for printing
        var module_name_utf8: [260]u8 = undefined;
        const module_name_len = unicode.utf16LeToUtf8(&module_name_utf8, curr_name) catch {
            std.debug.print("[-] Failed to convert module name to UTF-8\n", .{});
            continue;
        };

        std.debug.print("[+] Module: {s} at 0x{x}\n", .{ module_name_utf8[0..module_name_len], @intFromPtr(curr_module.DllBase) });

        var i: usize = 0;
        while (i < module_name.len and i < curr_name.len) {
            const c1 = std.ascii.toLower(@as(u8, @intCast(module_name[i])));
            const c2 = std.ascii.toLower(@as(u8, @intCast(curr_name[i])));
            if (c1 != c2) break;
            i += 1;
        }

        if (i == module_name.len and i == curr_name.len) {
            std.debug.print("[+] Found module at base address: 0x{x}\n", .{@intFromPtr(curr_module.DllBase)});
            return curr_module.DllBase;
        }

        curr_module = @as(*LDR_DATA_TABLE_ENTRY, @ptrCast(@alignCast(curr_module.InLoadOrderModuleList.Flink)));
    }

    std.debug.print("----------------------------------------\n", .{});
    std.debug.print("[-] Module not found\n", .{});
    return null;
}

pub fn main() !void {
    std.debug.print("Key: 0x{x}\n", .{g_KEY});
    std.debug.print("ASCII Hash: 0x{x}\n", .{ASCII_HASH});
    std.debug.print("Wide Hash: 0x{x}\n", .{WIDE_HASH});

    // Verify GetPEB works
    const peb = GetPEB();
    std.debug.print("\nPEB Verification:\n", .{});
    std.debug.print("PEB Address: 0x{x}\n", .{@intFromPtr(peb)});
    std.debug.print("BeingDebugged: {}\n", .{peb.BeingDebugged});

    // Verify Ldr field
    if (peb.Ldr) |ldr| {
        std.debug.print("Ldr Address: 0x{x}\n", .{@intFromPtr(ldr)});
        std.debug.print("InLoadOrderModuleList: 0x{x}\n", .{@intFromPtr(&ldr.InLoadOrderModuleList)});
    } else {
        std.debug.print("Ldr is null!\n", .{});
    }

    // Verify ProcessParameters
    if (peb.ProcessParameters) |params| {
        std.debug.print("ProcessParameters Address: 0x{x}\n", .{@intFromPtr(params)});
        std.debug.print("ImagePathName Length: {}\n", .{params.ImagePathName.Length});
        std.debug.print("CommandLine Length: {}\n", .{params.CommandLine.Length});
    } else {
        std.debug.print("ProcessParameters is null!\n", .{});
    }
}

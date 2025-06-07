const std = @import("std");
const unicode = std.unicode;
const win = std.os.windows;
const win32 = @import("win32");

// Windows types
const PVOID = win.PVOID;
const ULONG = win.ULONG;
const LIST_ENTRY = win.LIST_ENTRY;
const UNICODE_STRING = win.UNICODE_STRING;
const HANDLE = win.HANDLE;
pub const BOOLEAN = win.BOOLEAN;
pub const UCHAR = win.UCHAR;
pub const HMODULE = win.HMODULE;
pub const DWORD = win.DWORD;
const HINSTANCE = win.HINSTANCE;

pub const PEB = extern struct { InheritedAddressSpace: BOOLEAN, ReadImageFileExecOptions: BOOLEAN, BeingDebugged: BOOLEAN, BitField: UCHAR, Mutant: HANDLE, ImageBaseAddress: HMODULE, Ldr: ?*PEB_LDR_DATA };

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

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Reserved5: [3]PVOID,
    DUMMYUNIONNAME: extern union {
        CheckSum: ULONG,
        Reserved6: PVOID,
    },
    TimeDateStamp: ULONG,
};

// Compile-time seed using build timestamp
fn RandomCompileTimeSeed() u32 {
    const timestamp_str = @embedFile("timestamp.txt");
    var sum: u32 = 0;
    for (timestamp_str) |c| {
        sum = sum *% 31 +% c;
    }
    return sum;
}

// fn GetPEB() *PEB {
//     return asm volatile (
//         \\ movq %%gs:0x60, %[result]
//         : [result] "=r" (-> *PEB),
//     );
// }

// fn GetTEB() *TEB {
//     return asm volatile (
//         \\ movq %%gs:0x30, %[result]
//         : [result] "=r" (-> *TEB),
//     );
// }

// implement compile time hashing algorithms
// djb2 wide
// fn HashStringDjb2W(String: [*:0]const u16, key: u32) u32 {
//     var Hash: u32 = key;
//     var i: usize = 0;
//     while (String[i] != 0) : (i += 1) {
//         Hash = @as(u32, @truncate((@as(u64, Hash) << SEED) +
//             @as(u64, Hash) +
//             @as(u64, String[i])));
//     }
//     return Hash;
// }

fn HashString(s: []const u8) u64 {
    var hash: u64 = 5381;
    for (s) |c| {
        // We must use @addWithOverflow and @shlWithOverflow, as Zig would declare comptime error because of the overflow
        // The builtins return tuples with two values - the result in [0] and overflow bit in [1]
        hash = @addWithOverflow(@shlWithOverflow(hash, 5)[0], hash + std.ascii.toUpper(c))[0];
    }
    return hash;
}

// Function returns !?HINSTANCE.
// ! - function can return an error. The utf16LeToUtf8Alloc function can fail, and we do not handle any errors inside the function.
// ? - function can return null. Zig does not allow pointers to null, instead it uses optionals which can either be null or pointers.
// This makes Zig safer, as you must be explicit when dereferencing null pointers
// Lastly, the function returns HINSTANCE. This is basically a pointer to the DLL in memory.
fn getModuleHandleHash(comptime moduleName: []const u8) !?HINSTANCE {
    // We compute the hash of the searched module at compile time using the comptime keyword

    const moduleHash = comptime HashString(moduleName);
    // From here, the function is the same as previous example
    const peb = std.os.windows.peb();

    var buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;
    while (true) {
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        if (mod_name_length == 0) break;

        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer.?[0..mod_name_length]);
        // Instead of prtinting, we try if the hash matches with the searched hash
        if (HashString(mod_name_utf8) == moduleHash) {
            return @ptrCast(loaded_module.DllBase);
        }
        alloc.free(mod_name_utf8);
        modules_linked_list = modules_linked_list.Flink;
    }
    std.debug.print("Module not found in loaded DLLs.\n", .{});
    return null;
}

pub fn traverseLoadedDlls(dba: std.mem.Allocator) !void {
    // Get the PEB and access the LDR field
    const peb = std.os.windows.peb();

    // Get the first entry in the InMemoryOrderModuleList
    var modules_list = peb.Ldr.InLoadOrderModuleList.Flink;

    std.debug.print("\n[+] Starting module search\n", .{});

    while (true) {
        const curr_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_list);
        // Get the current module name

        // Get the name of the module from base dll name
        const module_name_utf16 = curr_module.BaseDllName.Buffer;
        const module_name_len = curr_module.BaseDllName.Length / @sizeOf(u16);

        // check if the module name is empty
        if (module_name_utf16 == null or module_name_len == 0) {
            break;
        }

        // we can print the module name by converting it to UTF-8
        const module_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(dba, curr_module.BaseDllName.Buffer.?[0..module_name_len]);

        defer dba.free(module_name_utf8);

        std.debug.print("{s} : {}\n", .{ module_name_utf8, curr_module.DllBase });

        modules_list = modules_list.Flink;
    }

    std.debug.print("----------------------------------------\n", .{});
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const dba = gpa.allocator();

    traverseLoadedDlls(dba) catch |err| {
        std.debug.print("Error traversing loaded DLLs: {}\n", .{err});
        return err;
    };

    // Example usage of getModuleHandleHash
    const handle = getModuleHandleHash("user32.dll") catch |err| {
        std.debug.print("Error getting module handle: {}\n", .{err});
        return err;
    };
    _ = handle;
}

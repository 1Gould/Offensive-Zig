const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;
const HANDLE = win.HANDLE;
const DWORD = win.DWORD;
const BOOL = win.BOOL;
const WINAPI = win.WINAPI;
const core = @import("core.zig");

// constants
const PROCESS_NAME = "notepad.exe";
const PROCESS_NAME_WIDE = "Notepad.exe";
const module_name = "kernel32.dll";

pub fn main() !void {
    var debug = std.heap.DebugAllocator(.{}){};
    const alloc = debug.allocator();

    var processId: u32 = undefined;
    var hProcess: HANDLE = undefined;

    std.debug.print("-------------------------------------------------\nTesting GetRemoteProcessHandle()\n", .{}); // Get remote process handle test
    if (!core.GetRemoteProcessHandle(PROCESS_NAME, &processId, &hProcess)) {
        std.debug.print("[-] GetRemoteProcessHandle() failed.\n", .{});
    }
    var flags: DWORD = undefined;
    if (core.GetHandleInformation(hProcess, &flags) == win.TRUE) {
        const pid = core.GetProcessId(hProcess);
        std.debug.print("[+] Process Handle: {any} (Flags: 0x{x}, Verified PID: {d})\n", .{ hProcess, flags, pid });
    } else {
        std.debug.print("[+] Process Handle: {any}\n", .{hProcess});
    }

    std.debug.print("-------------------------------------------------\nTesting GetRemoteProcessId()\n", .{});

    // Get remote process id test
    const process_id_ascii = core.GetRemoteProcessId(PROCESS_NAME) catch |err| {
        std.debug.print("[-] GetRemoteProcessId() failed: {}\n", .{err});
        return;
    };
    std.debug.print("[+] GetRemoteProcessId() succeeded: {}\n", .{process_id_ascii});

    std.debug.print("-------------------------------------------------\nTesting GetRemoteProcessIdW()\n", .{});
    // Get remote process id test
    const PROCESS_NAME_UNICODE = unicode.utf8ToUtf16LeAllocZ(alloc, PROCESS_NAME_WIDE) catch undefined;

    const process_id = core.GetRemoteProcessIdW(PROCESS_NAME_UNICODE) catch |err| {
        std.debug.print("[-] GetRemoteProcessIdW() failed: {}\n", .{err});
        return;
    };
    std.debug.print("[+] GetRemoteProcessIdW() succeeded: {}\n", .{process_id});

    std.debug.print("-------------------------------------------------\nTesting GetRemoteProcessHandleW()\n", .{});
    // Get remote process handle test (wide)
    if (!core.GetRemoteProcessHandleW(PROCESS_NAME_UNICODE, &processId, &hProcess)) {
        std.debug.print("[-] GetRemoteProcessHandleW() failed.\n", .{});
    }

    if (core.GetHandleInformation(hProcess, &flags) == win.TRUE) {
        const pid = core.GetProcessId(hProcess);
        std.debug.print("[+] Process Handle (wide): {any} (Flags: 0x{x}, Verified PID: {d})\n", .{ hProcess, flags, pid });
    } else {
        std.debug.print("[+] Process Handle (wide): {any}\n", .{hProcess});
    }

    std.debug.print("-------------------------------------------------\n", .{});

    // Test GetModuleName
    std.debug.print("Testing GetModuleName\n", .{});
    const wide_name = try unicode.utf8ToUtf16LeAllocZ(alloc, module_name);
    defer alloc.free(wide_name);

    const base_address = if (core.GetModuleName(wide_name)) |addr| addr else {
        std.debug.print("[-] Failed to find {s}\n", .{module_name});
        return;
    };
    std.debug.print("[+] Successfully found {s} at 0x{x}\n", .{ module_name, @intFromPtr(base_address) });

    std.debug.print("-------------------------------------------------\n", .{});
}

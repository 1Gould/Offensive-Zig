const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;
const HANDLE = win.HANDLE;
const DWORD = win.DWORD;
const BOOL = win.BOOL;
const WINAPI = win.WINAPI;
const core = @import("core.zig");
const win32 = @import("win32");

// constants
const PROCESS_NAME = "notepad.exe";
const PROCESS_NAME_WIDE = "Notepad.exe";

pub fn main() !void {
    var debug = std.heap.DebugAllocator(.{}){};
    const alloc = debug.allocator();
    _ = alloc;

    std.debug.print("-------------------------------------------------\nCurrent Process Information\n", .{});
    const currentProcess = win.GetCurrentProcess();
    const currentProcessId = win.GetCurrentProcessId();
    const currentThread = win.GetCurrentThread();
    const currentThreadId = win.GetCurrentThreadId();

    std.debug.print("[+] Current Process Handle: {any}\n", .{currentProcess});
    std.debug.print("[+] Current Process ID: {d}\n", .{currentProcessId});
    std.debug.print("[+] Current Thread Handle: {any}\n", .{currentThread});
    std.debug.print("[+] Current Thread ID: {d}\n", .{currentThreadId});

    // win.WaitForSingleObject(handle: currentThread, milliseconds: 1000);
    // win.WaitForSingleObjectEx(handle: currentThread, milliseconds: 1000, alertable: false);

    // win.CreateProcessW(lpApplicationName: ?LPCWSTR, lpCommandLine: ?LPWSTR, lpProcessAttributes: ?*SECURITY_ATTRIBUTES, lpThreadAttributes: ?*SECURITY_ATTRIBUTES, bInheritHandles: BOOL, dwCreationFlags: DWORD, lpEnvironment: ?*anyopaque, lpCurrentDirectory: ?LPCWSTR, lpStartupInfo: *STARTUPINFOW, lpProcessInformation: *PROCESS_INFORMATION);

    // win.LoadLibraryW(lpLibFileName: [*:0]const u16);

    // win.peb();
    // win.teb();

    // some basic primitives
    // win.VirtualProtect(lpAddress: ?LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: *DWORD);
    // win.VirtualProtectEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: *DWORD);
    // win.ReadProcessMemory(handle: HANDLE, addr: ?LPVOID, buffer: []u8);
    // win.WriteProcessMemory(handle: HANDLE, addr: ?LPVOID, buffer: []const u8);

    // win.ProcessBaseAddress(handle: HANDLE);
    printNewline();
    std.debug.print("Testing GetModuleHandle()\n", .{});

    // Custom get module handle implementation
    const kernel32 = core.getModuleHandle("KERNEL32.DLL") catch |err| {
        std.debug.print("Error getting module handle: {}\n", .{err});
        return err;
    };
    std.debug.print("[+] Kernel32 Module Handle: {any}\n", .{kernel32});

    const kernel32_a = win32.system.library_loader.GetModuleHandleA("kernel32.dll") orelse {
        std.debug.print("Error getting module handle with GetModuleHandleA\n", .{});
        return;
    };
    std.debug.print("[+] Kernel32 Module Handle (A): {any}\n", .{kernel32_a});

    

    // Custom get proc address implementation
    const g_msgbox = win32.system.library_loader.GetProcAddress(kernel32, "MessageBoxA") orelse {
        std.debug.print("Error getting proc address for MessageBoxA\n", .{});
        return;
    };
    _ = g_msgbox;

    var processId: u32 = undefined;
    var hProcess: HANDLE = undefined;
    var flags: DWORD = undefined;

    // Get remote process handle test
    printNewline();
    std.debug.print("Testing GetRemoteProcessHandle()\n", .{});

    if (!core.GetRemoteProcessHandle(PROCESS_NAME, &processId, &hProcess)) {
        std.debug.print("[-] GetRemoteProcessHandle() failed.\n", .{});
    } else {
        const pid = core.GetProcessId(hProcess);
        _ = core.GetHandleInformation(hProcess, &flags);
        std.debug.print("[+] Process Handle: {any} (Flags: 0x{x}, Verified PID: {d})\n", .{ hProcess, flags, pid });
    }

    printNewline();
    std.debug.print("Testing GetRemoteProcessId()\n", .{});

    // Get remote process id test
    const process_id_ascii = core.GetRemoteProcessId(PROCESS_NAME) catch |err| {
        std.debug.print("[-] GetRemoteProcessId() failed: {}\n", .{err});
        return;
    };
    std.debug.print("[+] GetRemoteProcessId() succeeded: {}\n", .{process_id_ascii});
    printNewline();
}

// Unit tests

fn printNewline() void {
    std.debug.print("-------------------------------------------------\n", .{});
}

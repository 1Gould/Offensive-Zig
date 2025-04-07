const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;
const HANDLE = win.HANDLE;
const DWORD = win.DWORD;
const BOOL = win.BOOL;
const WINAPI = win.WINAPI;
const CHAR = win.CHAR;
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});

pub extern "kernel32" fn Process32FirstW(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32W,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn Process32NextW(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32W,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn Process32Next(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn Process32First(
    hSnapshot: HANDLE,
    lppe: *PROCESSENTRY32,
) callconv(WINAPI) BOOL;

pub const PROCESSENTRY32W = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u16,
};

pub const PROCESSENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]CHAR,
};

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(WINAPI) HANDLE;

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(WINAPI) DWORD;

pub extern "kernel32" fn GetHandleInformation(
    hObject: HANDLE,
    lpdwFlags: *DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn GetProcessId(
    Process: HANDLE,
) callconv(WINAPI) DWORD;

pub fn exit() noreturn {
    std.debug.print("Exiting...\n", .{});
    @import("std").process.exit(0);
}

pub fn GetRemoteProcessId(szProcessName: []const u8) anyerror!DWORD {
    const szProcessNameLength = szProcessName.len;

    var pName: [c.MAX_PATH]u8 = undefined;
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
        while (j < c.MAX_PATH and process_entry.szExeFile[j] != 0) {
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

pub fn GetRemoteProcessHandle(szProcessName: []const u8, dwProcessId: *u32, pProcess: *HANDLE) bool {
    // Define our length constant
    const szProcessNameLength = szProcessName.len;

    var pName: [c.MAX_PATH]u8 = undefined;
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
        while (j < c.MAX_PATH and process_entry.szExeFile[j] != 0) {
            process_entry.szExeFile[j] = std.ascii.toLower(process_entry.szExeFile[j]);
            j += 1;
        }
        // cast szExeFile to a sentinel-terminated pointer and create a slice
        const temp: [*c]u8 = @ptrCast(&process_entry.szExeFile);
        const exeFileName = std.mem.span(temp);

        if (std.mem.eql(u8, exeFileName, pName[0..szProcessNameLength])) {
            std.debug.print("[+] Found matching process: {s}, Process ID: {d}\n", .{ exeFileName, process_entry.th32ProcessID });

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

pub fn GetRemoteProcessIdW(szProcessName: []const u16) anyerror!DWORD {
    const szProcessNameLength = szProcessName.len;

    var process_entry: PROCESSENTRY32W = undefined;
    const snapshot = win.kernel32.CreateToolhelp32Snapshot(win.TH32CS_SNAPPROCESS, 0);
    defer win.CloseHandle(snapshot);

    process_entry.dwSize = @sizeOf(PROCESSENTRY32W);
    var loop = Process32FirstW(snapshot, &process_entry);
    if (loop == win.FALSE) {
        return error.ProcessNotFound;
    }

    while (loop == win.TRUE) : (loop = Process32NextW(snapshot, &process_entry)) {
        if (std.mem.eql(u16, process_entry.szExeFile[0..szProcessNameLength], szProcessName)) {
            return process_entry.th32ProcessID;
        }
    }

    return error.ProcessNotFound;
}

pub fn GetRemoteProcessHandleW(szProcessName: []const u16, dwProcessId: *u32, pProcess: *HANDLE) bool {
    var process_entry: PROCESSENTRY32W = undefined;
    process_entry.dwSize = @sizeOf(PROCESSENTRY32W);

    // Convert Unicode to UTF-8 for printing
    var utf8_buffer: [260]u8 = undefined;
    const utf8_len = unicode.utf16LeToUtf8(&utf8_buffer, szProcessName) catch {
        std.debug.print("[-] Failed to convert process name to UTF-8\n", .{});
        return false;
    };
    std.debug.print("[+] Looking for process (wide): {s}\n", .{utf8_buffer[0..utf8_len]});

    const snapshot = win.kernel32.CreateToolhelp32Snapshot(win.TH32CS_SNAPPROCESS, 0);
    if (snapshot == win.INVALID_HANDLE_VALUE) {
        std.debug.print("[-] CreateToolhelp32Snapshot() failed.\n", .{});
        return false;
    }

    defer win.CloseHandle(snapshot);

    var loop = Process32FirstW(snapshot, &process_entry);
    if (loop == win.FALSE) {
        std.debug.print("[-] Process32FirstW() failed.\n", .{});
        return false;
    }

    while (loop == win.TRUE) : (loop = Process32NextW(snapshot, &process_entry)) {
        if (std.mem.eql(u16, process_entry.szExeFile[0..szProcessName.len], szProcessName)) {
            // Convert process name to UTF-8 for printing
            var process_name_utf8: [260]u8 = undefined;
            const process_name_len = unicode.utf16LeToUtf8(&process_name_utf8, process_entry.szExeFile[0..szProcessName.len]) catch {
                std.debug.print("[-] Failed to convert process name to UTF-8\n", .{});
                return false;
            };
            std.debug.print("[+] Found matching process (wide): {s}, Process ID: {d}\n", .{ process_name_utf8[0..process_name_len], process_entry.th32ProcessID });

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

// DEPRECATED
// pub fn GetRemoteProcessHandle(szProcessName: []const u8, dwProcessId: *u32, pProcess: *HANDLE) bool {
//     // Define our length constant
//     const szProcessNameLength = szProcessName.len;

//     var pName: [c.MAX_PATH]u8 = undefined;
//     @memcpy(pName[0..szProcessNameLength], szProcessName[0..szProcessNameLength]);

//     // Convert to lower case
//     var t: usize = 0;
//     while (t < szProcessNameLength) {
//         pName[t] = std.ascii.toLower(pName[t]);
//         t += 1;
//     }

//     // Define our struct to hold the process information
//     var Proc: c.PROCESSENTRY32 = undefined;
//     Proc.dwSize = @sizeOf(c.PROCESSENTRY32);

//     const hSnapShot = c.CreateToolhelp32Snapshot(c.TH32CS_SNAPPROCESS, 0);
//     if (hSnapShot == c.INVALID_HANDLE_VALUE or hSnapShot == null) {
//         std.debug.print("[+] Unable to create snapshot, CreateToolhelp32Snapshot() failed.\n", .{});
//         return false;
//     }

//     var bRet = c.Process32First(hSnapShot, &Proc);

//     std.debug.print("[+] Looking for process: {s}\n", .{pName[0..szProcessNameLength]});

//     while (bRet != 0) { // While there are processes, keep looping

//         // convert Proc.szExeFile to lower case
//         var j: usize = 0;
//         while (j < c.MAX_PATH and Proc.szExeFile[j] != 0) {
//             Proc.szExeFile[j] = std.ascii.toLower(Proc.szExeFile[j]);
//             j += 1;
//         }
//         // cast szExeFile to a sentinel-terminated pointer and create a slice
//         const temp: [*c]u8 = @ptrCast(&Proc.szExeFile);
//         const exeFileName = std.mem.span(temp);
//         std.debug.print("[+] Found process: {s}\n", .{exeFileName});
//         std.debug.print("[+] Found process ID: {d}\n", .{Proc.th32ProcessID});

//         // compare the process name to the name we are looking for
//         std.debug.print("[+] Comparing process name: {s} to {s}\n", .{ exeFileName, pName[0..szProcessNameLength] });

//         if (std.mem.eql(u8, exeFileName, pName[0..szProcessNameLength])) {
//             std.debug.print("[+] Assigning ProcessID.\n", .{});
//             // TODO: figure out how to cast this correctly, segfault
//             // dwProcessId.* = Proc.th32ProcessID;
//             _ = dwProcessId;

//             // Open the process
//             std.debug.print("[+] Opening Process.\n", .{});
//             const processHandle = OpenProcess(0x1fffff, 0, Proc.th32ProcessID);
//             std.debug.print("[+] Assigning Process Handle.\n", .{});
//             pProcess.* = processHandle;
//             return true;
//         }
//         bRet = c.Process32Next(hSnapShot, &Proc);
//     }

//     if (c.CloseHandle(hSnapShot) == 0) {
//         std.debug.print("[+] Unable to close snapshot, CloseHandle() failed.\n", .{});
//         return false;
//     }

//     return false;
// }

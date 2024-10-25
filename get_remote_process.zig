const std = @import("std");
const root = @import("root.zig");
const win = std.os.windows;
const unicode = std.unicode;
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: win.DWORD,
    bInheritHandle: win.BOOL,
    dwProcessId: win.DWORD,
) callconv(win.WINAPI) win.HANDLE;

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: win.HANDLE,
    dwMilliseconds: win.DWORD,
) callconv(win.WINAPI) win.DWORD;


pub fn main() !void {
    const processName = "Notepad.exe";
    var hProcess: win.HANDLE = undefined;
    const pProcess: *win.HANDLE = &hProcess;
    const dwProcessId: *u32 = undefined;

    _ = c.SetConsoleOutputCP(c.CP_UTF8);

    if (!GetRemoteProcessHandle(processName, dwProcessId, pProcess)) {
        std.debug.print("[-] GetRemoteProcessHandle() failed.\n", .{});
    }
    std.debug.print("[+] GetRemoteProcessHandle() succeeded.\n", .{});

    _ = WaitForSingleObject(hProcess, win.INFINITE);
}

pub fn exit() noreturn {
    std.debug.print("Exiting...\n", .{});
    @import("std").process.exit(0);
}


pub fn GetRemoteProcessHandle(szProcessName: []const u8, dwProcessId: *u32, pProcess: *win.HANDLE) bool {
    // Define our length constant
    const szProcessNameLength = szProcessName.len;

    var pName: [c.MAX_PATH]u8 = undefined;
    @memcpy(pName[0..szProcessNameLength], szProcessName[0..szProcessNameLength]);

    // Convert to lower case
    var t: usize = 0;
    while (t < szProcessNameLength) {
        pName[t] = std.ascii.toLower(pName[t]);
        t += 1;
    }

    // Define our struct to hold the process information
    var Proc = comptime c.PROCESSENTRY32{
        .dwSize = @sizeOf(c.PROCESSENTRY32),
        .cntUsage = undefined,
        .th32ProcessID = undefined,
        .th32DefaultHeapID = undefined,
        .th32ModuleID = undefined,
        .cntThreads = undefined,
        .th32ParentProcessID = undefined,
        .pcPriClassBase = undefined,
        .dwFlags = undefined,
        .szExeFile = undefined,
    };

    const hSnapShot = c.CreateToolhelp32Snapshot(c.TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == c.INVALID_HANDLE_VALUE or hSnapShot == null) {
        std.debug.print("[+] Unable to create snapshot, CreateToolhelp32Snapshot() failed.\n", .{});
        return false;
    }

    var bRet = c.Process32First(hSnapShot, &Proc);

    std.debug.print("[+] Looking for process: {s}\n", .{pName[0..szProcessNameLength]});

    while (bRet != 0) { // While there are processes, keep looping

        // convert Proc.szExeFile to lower case
        var j: usize = 0;
        while (j < c.MAX_PATH and Proc.szExeFile[j] != 0) {
            Proc.szExeFile[j] = std.ascii.toLower(Proc.szExeFile[j]);
            j += 1;
        }
        // cast szExeFile to a sentinel-terminated pointer and create a slice
        const temp: [*c]u8 = @ptrCast(&Proc.szExeFile);
        const exeFileName = std.mem.span(temp);
        std.debug.print("[+] Found process: {s}\n", .{exeFileName});
        std.debug.print("[+] Found process ID: {d}\n", .{Proc.th32ProcessID});

        // compare the process name to the name we are looking for
        std.debug.print("[+] Comparing process name: {s} to {s}\n", .{ exeFileName, pName[0..szProcessNameLength] });

        if (std.mem.eql(u8, exeFileName, pName[0..szProcessNameLength])) {
            std.debug.print("[+] Assigning ProcessID.\n", .{});
			// TODO: figure out how to cast this correctly, segfault
            // dwProcessId.* = Proc.th32ProcessID;
            _ = dwProcessId;

            // Open the process
            std.debug.print("[+] Opening Process.\n", .{});
            const processHandle = OpenProcess(0x1fffff, 0, Proc.th32ProcessID);
            std.debug.print("[+] Assigning Process Handle.\n", .{});
            pProcess.* = processHandle;
            break;
        }
        bRet = c.Process32Next(hSnapShot, &Proc);
    }

    if (c.CloseHandle(hSnapShot) == 0) {
        std.debug.print("[+] Unable to close snapshot, CloseHandle() failed.\n", .{});
        return false;
    }

    return true;
}

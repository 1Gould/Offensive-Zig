const std = @import("std");
const root = @import("root.zig");
const win = std.os.windows;
const unicode = std.unicode;
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});

const ProcessIdentifier = struct {
    processId: win.DWORD,
    handle: win.HANDLE,
};


pub fn GetRemoteProcessHandle(szProcessName: []const u8) !ProcessIdentifier {
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
        return error.SnapshotCreationFailed;
    }

    var hProcess: ?win.HANDLE = null;
    var dwProcessId: win.DWORD = 0;
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
            std.debug.print("[+] Comparing process name: {s} to {s}\n", .{exeFileName, pName[0..szProcessNameLength]});
            // std.debug.print("Length of Proc.szExeFile: {s}\n", .{&Proc.szExeFile});
            // std.debug.print("Length of pName slice: {d}\n", .{szProcessNameLength});
            // std.debug.print("Raw bytes of Proc.szExeFile: {x}\n", .{&Proc.szExeFile});
            // std.debug.print("Raw bytes of pName slice: {x}\n", .{pName[0..szProcessNameLength]});

            if (std.mem.eql(u8, exeFileName, pName[0..szProcessNameLength])) {
                dwProcessId = Proc.th32ProcessID;
                hProcess = c.OpenProcess(c.PROCESS_ALL_ACCESS, win.FALSE, dwProcessId);
                if (hProcess == null) {
                    _ = c.CloseHandle(hSnapShot);
                    std.debug.print("[+] Unable to open process: {s}\n", .{exeFileName});
                    return error.ProcessOpenFailed;
                }
                break;
            }
            bRet = c.Process32Next(hSnapShot, &Proc);
        }
    

    if (c.CloseHandle(hSnapShot) == 0) {
        std.debug.print("[+] Unable to close snapshot, CloseHandle() failed.\n", .{});
        return error.SnapshotCloseFailed;
    }

    if (hProcess) |validHandle| {
        std.debug.print("[+] Successfully retrieved handle.\n", .{});

        return ProcessIdentifier{
            .handle = validHandle,
            .processId = dwProcessId,
        };
    } else {
        // Handle the case where hProcess is null
        std.debug.print("[+] Unable to find process: {s}\n", .{pName[0..szProcessNameLength]});
        return error.ProcessNotFound;
    }
}

pub fn main() !void {
    const processName = "Notepad.exe";

    _ = c.SetConsoleOutputCP(c.CP_UTF8);

    const result = try GetRemoteProcessHandle(processName);
    std.debug.print("----------------------------\n[+] Process handle: {x}\n[+] Process ID: {d}\n----------------------------\n", .{&(result.handle), result.processId});
}


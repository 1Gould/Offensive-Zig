const std = @import("std");
const root = @import("root.zig");
const win = std.os.windows;
const unicode = std.unicode;
const c = @cImport(@cInclude("windows.h"));

const ProcessIdentifier = struct {
    processId: win.DWORD,
    handle: win.HANDLE,
};

pub fn main() !void {
    const processName = "Notepad.exe";

    _ = c.SetConsoleOutputCP(c.CP_UTF8);

    const result = try root.GetRemoteProcessHandle(processName);
    std.debug.print("----------------------------\n[+] Process handle: {x}\n[+] Process ID: {d}\n----------------------------\n", .{&(result.handle), result.processId});
}
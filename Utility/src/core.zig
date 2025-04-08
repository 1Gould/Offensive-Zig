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

// Define CREATE_SUSPENDED constant
const CREATE_SUSPENDED = 0x00000004;

// External function declarations for process creation

pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

pub const TEB = extern struct {
    NtTib: NT_TIB,
    EnvironmentPointer: *anyopaque,
    ClientId: CLIENT_ID,
    ActiveRpcHandle: *anyopaque,
    ThreadLocalStoragePointer: *anyopaque,
    ProcessEnvironmentBlock: *PEB,
    LastErrorValue: DWORD,
    CountOfOwnedCriticalSections: DWORD,
    CsrClientThread: *anyopaque,
    Win32ThreadInfo: *anyopaque,
    User32Reserved: [26]DWORD,
    UserReserved: [5]DWORD,
    WOW32Reserved: *anyopaque,
    CurrentLocale: DWORD,
    FpSoftwareStatusRegister: DWORD,
    SystemReserved1: [54]DWORD,
    ExceptionCode: DWORD,
    ActivationContextStackPointer: *anyopaque,
    SpareBytes1: [24]u8,
    GdiTebBatch: [1248]u8,
    RealClientId: CLIENT_ID,
    GdiCachedProcessHandle: HANDLE,
    GdiClientPID: DWORD,
    GdiClientTID: DWORD,
    GdiThreadLocalInfo: *anyopaque,
    Win32ClientInfo: [62]DWORD,
    glDispatchTable: [233]DWORD,
    glReserved1: [29]DWORD,
    glReserved2: *anyopaque,
    glSectionInfo: *anyopaque,
    glSection: *anyopaque,
    glTable: *anyopaque,
    glCurrentRC: *anyopaque,
    glContext: *anyopaque,
    LastStatusValue: DWORD,
    StaticUnicodeString: UNICODE_STRING,
    StaticUnicodeBuffer: [261]u16,
    DeallocationStack: *anyopaque,
    TlsSlots: [64]DWORD,
    TlsLinks: LIST_ENTRY,
    Vdm: *anyopaque,
    ReservedForNtRpc: *anyopaque,
    DbgSsReserved: [2]DWORD,
    HardErrorMode: DWORD,
    Instrumentation: [16]DWORD,
    WinSockData: *anyopaque,
    GdiBatchCount: DWORD,
    InDbgPrint: BOOL,
    FreeStackOnTermination: BOOL,
    HasFiberData: BOOL,
    IdealProcessor: DWORD,
    GuaranteedStackBytes: DWORD,
    ReservedForPerf: *anyopaque,
    ReservedForOle: *anyopaque,
    WaitingOnLoaderLock: DWORD,
    SavedPriorityState: *anyopaque,
    ReservedForCodeCoverage: DWORD,
    ThreadPoolData: *anyopaque,
    TlsExpansionSlots: *anyopaque,
    DeallocationBStore: *anyopaque,
    BStoreLimit: *anyopaque,
    ImpersonationLocale: DWORD,
    IsImpersonating: BOOL,
    NlsCache: *anyopaque,
    pShimData: *anyopaque,
    HeapVirtualAffinity: DWORD,
    CurrentTransactionHandle: *anyopaque,
    ActiveFrame: *anyopaque,
    FlsData: *anyopaque,
    PreferredLanguages: *anyopaque,
    UserPrefLanguages: *anyopaque,
    MergedPrefLanguages: *anyopaque,
    MuiImpersonation: DWORD,
    CrossTebFlags: u16,
    SameTebFlags: u16,
    TxnScopeEnterCallback: *anyopaque,
    TxnScopeExitCallback: *anyopaque,
    TxnScopeContext: *anyopaque,
    LockCount: DWORD,
    WowTebOffset: DWORD,
    ResourceRetValue: *anyopaque,
    ReservedForWdf: *anyopaque,
    ReservedForCrt: *anyopaque,
    EffectiveContainerId: GUID,
};

pub const NT_TIB = extern struct {
    ExceptionList: *anyopaque,
    StackBase: *anyopaque,
    StackLimit: *anyopaque,
    SubSystemTib: *anyopaque,
    FiberData: *anyopaque,
    ArbitraryUserPointer: *anyopaque,
    Self: *NT_TIB,
};

pub const CLIENT_ID = extern struct {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
};
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
) callconv(WINAPI) win.BOOL;

extern "kernel32" fn VirtualAllocEx(
    hProcess: win.HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: win.DWORD,
    flProtect: win.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern "kernel32" fn WriteProcessMemory(
    hProcess: win.HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(WINAPI) win.BOOL;

extern "kernel32" fn CreateRemoteThread(
    hProcess: win.HANDLE,
    lpThreadAttributes: ?*win.SECURITY_ATTRIBUTES,
    dwStackSize: win.SIZE_T,
    lpStartAddress: win.LPTHREAD_START_ROUTINE,
    lpParameter: ?win.LPVOID,
    dwCreationFlags: win.DWORD,
    lpThreadId: ?*win.DWORD,
) callconv(WINAPI) ?win.HANDLE;

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

pub const PEB = extern struct {
    Reserved1: [2]u8,
    BeingDebugged: u8,
    Reserved2: [1]u8,
    Reserved3: [2]u32,
    Ldr: *PEB_LDR_DATA,
    ProcessParameters: *RTL_USER_PROCESS_PARAMETERS,
    Reserved4: [3]u32,
    AtlThunkSListPtr: u32,
    Reserved5: u32,
    Reserved6: u32,
    Reserved7: u32,
    Reserved8: u32,
    AtlThunkSListPtr32: u32,
    Reserved9: [45]u32,
    Reserved10: [96]u8,
    PostProcessInitRoutine: u32,
    Reserved11: [128]u8,
    Reserved12: [1]u32,
    SessionId: u32,
};

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

pub const IMAGE_NT_HEADERS = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_OPTIONAL_HEADER = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    DllBase: ?*anyopaque,
    EntryPoint: ?*anyopaque,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: u32,
    LoadCount: u16,
    TlsIndex: u16,
    HashLinks: LIST_ENTRY,
    TimeDateStamp: u32,
};

pub const PEB_LDR_DATA = extern struct {
    Length: u32,
    Initialized: u8,
    SsHandle: ?*anyopaque,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    EntryInProgress: ?*anyopaque,
    ShutdownInProgress: u8,
    ShutdownThreadId: HANDLE,
};

pub const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const RTL_USER_PROCESS_PARAMETERS = extern struct {
    Reserved1: [16]u8,
    Reserved2: [10]u32,
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
};

pub const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: [*]u16,
};

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

pub fn GetPEB() *win.PEB {
    return asm volatile (
        \\ movq %%gs:0x60, %[result]
        : [result] "=r" (-> *win.PEB),
    );
}

pub fn GetTEB() *TEB {
    return asm volatile (
        \\ movq %%gs:0x30, %[result]
        : [result] "=r" (-> *TEB),
    );
}

pub fn CreateSuspendedProcess(process_name: []const u8) !HANDLE {
    const alloc: std.mem.Allocator = std.heap.page_allocator;

    // Create UTF-16 command line for the process
    const wide_cmd_line = try unicode.utf8ToUtf16LeAllocZ(alloc, process_name);
    defer alloc.free(wide_cmd_line);

    // Initialize process startup info
    var startup_info: win.STARTUPINFOW = std.mem.zeroes(win.STARTUPINFOW);
    startup_info.cb = @sizeOf(win.STARTUPINFOW);
    var process_info: win.PROCESS_INFORMATION = undefined;

    // Create process in a suspended state
    const creation_result = CreateProcessW(
        null,
        wide_cmd_line.ptr,
        null,
        null,
        win.FALSE,
        CREATE_SUSPENDED,
        null,
        null,
        &startup_info,
        &process_info,
    );

    if (creation_result == 0) {
        std.debug.print("[+] CreateProcessW failed: {}\n", .{win.kernel32.GetLastError()});
        return error.CreateProcessFailed;
    }

    // Close the thread handle since we don't need it
    _ = win.CloseHandle(process_info.hThread);

    // Return the process handle
    return process_info.hProcess;
}

// convert the string to a wide string UTF16-L in comptime
fn ComptimeWS(comptime str: []const u8) []const u16 {
    @setEvalBranchQuota(100_000_000);
    comptime {
        var wide_str = std.unicode.utf8ToUtf16LeStringLiteral(str);
        _ = &wide_str; // ignore
        return wide_str;
    }
}

pub fn GetModuleName(module_name: []const u16) ?*anyopaque {
    const peb = GetPEB();
    const ldr = peb.Ldr;
    var curr_module = @as(*LDR_DATA_TABLE_ENTRY, @ptrCast(@alignCast(ldr.InLoadOrderModuleList.Flink)));

    std.debug.print("\n[+] Starting module search\n", .{});

    while (curr_module.DllBase != null) {
        const buffer_ptr = @as(?[*]u16, @ptrCast(curr_module.BaseDllName.Buffer));
        if (buffer_ptr == null) {
            curr_module = @as(*LDR_DATA_TABLE_ENTRY, @ptrCast(@alignCast(curr_module.InLoadOrderModuleList.Flink)));
            continue;
        }

        const curr_name = curr_module.BaseDllName.Buffer[0 .. curr_module.BaseDllName.Length / 2];

        // Convert module name to UTF-8 for printing
        var module_name_utf8: [260]u8 = undefined;
        const module_name_len = unicode.utf16LeToUtf8(&module_name_utf8, curr_name) catch {
            std.debug.print("[-] Failed to convert module name to UTF-8\n", .{});
            continue;
        };

        std.debug.print("[+] Module: {s} at 0x{x}\n", .{ module_name_utf8[0..module_name_len], @intFromPtr(curr_module.DllBase) });

        var i: usize = 0;
        while (i < module_name.len and i < curr_name.len) {
            const c1 = std.ascii.toLower(@as(u8, @intCast(module_name[i])));
            const c2 = std.ascii.toLower(@as(u8, @intCast(curr_name[i])));
            if (c1 != c2) break;
            i += 1;
        }

        if (i == module_name.len and i == curr_name.len) {
            std.debug.print("[+] Found module at base address: 0x{x}\n", .{@intFromPtr(curr_module.DllBase)});
            return curr_module.DllBase;
        }

        curr_module = @as(*LDR_DATA_TABLE_ENTRY, @ptrCast(@alignCast(curr_module.InLoadOrderModuleList.Flink)));
    }

    std.debug.print("----------------------------------------\n", .{});
    std.debug.print("[-] Module not found\n", .{});
    return null;
}

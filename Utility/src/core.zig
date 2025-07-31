const std = @import("std");
const win = std.os.windows;
const unicode = std.unicode;
const win32 = @import("win32");

const c = @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});
// Windows types
const PVOID = win.PVOID;
const ULONG = win.ULONG;
const HANDLE = win.HANDLE;
pub const BOOLEAN = win.BOOLEAN;
pub const UCHAR = win.UCHAR;
pub const HMODULE = win.HMODULE;
const HINSTANCE = win.HINSTANCE;
const WINAPI = win.WINAPI;
const CHAR = win.CHAR;
const MAX_PATH = win.MAX_PATH;
const TRUE = win.TRUE;
const FALSE = win.FALSE;
const LONG = win.LONG;
const ULONG_PTR = win.ULONG_PTR;
const WORD = win.WORD;
const LARGE_INTEGER = win.LARGE_INTEGER;
const USHORT = win.USHORT;
const ULARGE_INTEGER = win.ULARGE_INTEGER;
const ULONGLONG = win.ULONGLONG;
const WCHAR = win.WCHAR;
const ULONG64 = win.ULONG64;
const INT = win.INT;
const DWORD64 = win.DWORD64;
const SECURITY_ATTRIBUTES = win.SECURITY_ATTRIBUTES;
const STARTUPINFOW = win.STARTUPINFOW;
const BOOL = win.BOOL;
const LPCWSTR = win.LPCWSTR;
const LPWSTR = win.LPWSTR;
const DWORD = win.DWORD;
const LPVOID = win.LPVOID;
const PROCESS_INFORMATION = win.PROCESS_INFORMATION;
const SIZE_T = win.SIZE_T;
const LPTHREAD_START_ROUTINE = win.LPTHREAD_START_ROUTINE;
const LPCVOID = win.LPCVOID;
const LPSECURITY_ATTRIBUTES = win.LPSECURITY_ATTRIBUTES;
const LPCSTR = win.LPCSTR;
const BYTE = win.BYTE;
const LONGLONG = win.LONGLONG;
const FARPROC = win.FARPROC;

// Define CREATE_SUSPENDED constant
const CREATE_SUSPENDED = 0x00000004;

pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

pub const RTL_CRITICAL_SECTION_DEBUG = extern struct {
    Type: WORD,
    CreatorBackTraceIndex: WORD,
    CriticalSection: *RTL_CRITICAL_SECTION,
    ProcessLocksList: LIST_ENTRY,
    EntryCount: DWORD,
    ContentionCount: DWORD,
    Flags: DWORD,
    CreatorBackTraceIndexHigh: WORD,
    SpareWORD: WORD,
};

pub const RTL_CRITICAL_SECTION = extern struct {
    DebugInfo: *RTL_CRITICAL_SECTION_DEBUG,
    LockCount: LONG,
    RecursionCount: LONG,
    OwningThread: HANDLE,
    LockSemaphore: HANDLE,
    SpinCount: ULONG_PTR,
};

pub const ACTIVATION_CONTEXT_DATA = opaque {};
pub const ASSEMBLY_STORAGE_MAP = opaque {};
pub const FLS_CALLBACK_INFO = opaque {};
pub const RTL_BITMAP = opaque {};
pub const KAFFINITY = usize;
pub const KPRIORITY = i32;

pub const PEB = extern struct {
    // Versions: All
    InheritedAddressSpace: BOOLEAN,

    // Versions: 3.51+
    ReadImageFileExecOptions: BOOLEAN,
    BeingDebugged: BOOLEAN,

    // Versions: 5.2+ (previously was padding)
    BitField: UCHAR,

    // Versions: all
    Mutant: HANDLE,
    ImageBaseAddress: HMODULE,
    Ldr: *PEB_LDR_DATA,
    ProcessParameters: *RTL_USER_PROCESS_PARAMETERS,
    SubSystemData: PVOID,
    ProcessHeap: HANDLE,

    // Versions: 5.1+
    FastPebLock: *RTL_CRITICAL_SECTION,

    // Versions: 5.2+
    AtlThunkSListPtr: PVOID,
    IFEOKey: PVOID,

    // Versions: 6.0+

    /// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/crossprocessflags.htm
    CrossProcessFlags: ULONG,

    // Versions: 6.0+
    union1: extern union {
        KernelCallbackTable: PVOID,
        UserSharedInfoPtr: PVOID,
    },

    // Versions: 5.1+
    SystemReserved: ULONG,

    // Versions: 5.1, (not 5.2, not 6.0), 6.1+
    AtlThunkSListPtr32: ULONG,

    // Versions: 6.1+
    ApiSetMap: PVOID,

    // Versions: all
    TlsExpansionCounter: ULONG,
    // note: there is padding here on 64 bit
    TlsBitmap: *RTL_BITMAP,
    TlsBitmapBits: [2]ULONG,
    ReadOnlySharedMemoryBase: PVOID,

    // Versions: 1703+
    SharedData: PVOID,

    // Versions: all
    ReadOnlyStaticServerData: *PVOID,
    AnsiCodePageData: PVOID,
    OemCodePageData: PVOID,
    UnicodeCaseTableData: PVOID,

    // Versions: 3.51+
    NumberOfProcessors: ULONG,
    NtGlobalFlag: ULONG,

    // Versions: all
    CriticalSectionTimeout: LARGE_INTEGER,

    // End of Original PEB size

    // Fields appended in 3.51:
    HeapSegmentReserve: ULONG_PTR,
    HeapSegmentCommit: ULONG_PTR,
    HeapDeCommitTotalFreeThreshold: ULONG_PTR,
    HeapDeCommitFreeBlockThreshold: ULONG_PTR,
    NumberOfHeaps: ULONG,
    MaximumNumberOfHeaps: ULONG,
    ProcessHeaps: *PVOID,

    // Fields appended in 4.0:
    GdiSharedHandleTable: PVOID,
    ProcessStarterHelper: PVOID,
    GdiDCAttributeList: ULONG,
    // note: there is padding here on 64 bit
    LoaderLock: *RTL_CRITICAL_SECTION,
    OSMajorVersion: ULONG,
    OSMinorVersion: ULONG,
    OSBuildNumber: USHORT,
    OSCSDVersion: USHORT,
    OSPlatformId: ULONG,
    ImageSubSystem: ULONG,
    ImageSubSystemMajorVersion: ULONG,
    ImageSubSystemMinorVersion: ULONG,
    // note: there is padding here on 64 bit
    ActiveProcessAffinityMask: KAFFINITY,
    GdiHandleBuffer: [
        switch (@sizeOf(usize)) {
            4 => 0x22,
            8 => 0x3C,
            else => unreachable,
        }
    ]ULONG,

    // Fields appended in 5.0 (Windows 2000):
    PostProcessInitRoutine: PVOID,
    TlsExpansionBitmap: *RTL_BITMAP,
    TlsExpansionBitmapBits: [32]ULONG,
    SessionId: ULONG,
    // note: there is padding here on 64 bit
    // Versions: 5.1+
    AppCompatFlags: ULARGE_INTEGER,
    AppCompatFlagsUser: ULARGE_INTEGER,
    ShimData: PVOID,
    // Versions: 5.0+
    AppCompatInfo: PVOID,
    CSDVersion: UNICODE_STRING,

    // Fields appended in 5.1 (Windows XP):
    ActivationContextData: *const ACTIVATION_CONTEXT_DATA,
    ProcessAssemblyStorageMap: *ASSEMBLY_STORAGE_MAP,
    SystemDefaultActivationData: *const ACTIVATION_CONTEXT_DATA,
    SystemAssemblyStorageMap: *ASSEMBLY_STORAGE_MAP,
    MinimumStackCommit: ULONG_PTR,

    // Fields appended in 5.2 (Windows Server 2003):
    FlsCallback: *FLS_CALLBACK_INFO,
    FlsListHead: LIST_ENTRY,
    FlsBitmap: *RTL_BITMAP,
    FlsBitmapBits: [4]ULONG,
    FlsHighIndex: ULONG,

    // Fields appended in 6.0 (Windows Vista):
    WerRegistrationData: PVOID,
    WerShipAssertPtr: PVOID,

    // Fields appended in 6.1 (Windows 7):
    pUnused: PVOID, // previously pContextData
    pImageHeaderHash: PVOID,

    /// TODO: https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/tracingflags.htm
    TracingFlags: ULONG,

    // Fields appended in 6.2 (Windows 8):
    CsrServerReadOnlySharedMemoryBase: ULONGLONG,

    // Fields appended in 1511:
    TppWorkerpListLock: ULONG,
    TppWorkerpList: LIST_ENTRY,
    WaitOnAddressHashTable: [0x80]PVOID,

    // Fields appended in 1709:
    TelemetryCoverageHeader: PVOID,
    CloudFileFlags: ULONG,
};

pub const PEB_LDR_DATA = extern struct {
    // Versions: 3.51 and higher
    /// The size in bytes of the structure
    Length: ULONG,

    /// TRUE if the structure is prepared.
    Initialized: BOOLEAN,

    SsHandle: PVOID,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,

    // Versions: 5.1 and higher

    /// No known use of this field is known in Windows 8 and higher.
    EntryInProgress: PVOID,

    // Versions: 6.0 from Windows Vista SP1, and higher
    ShutdownInProgress: BOOLEAN,

    /// Though ShutdownThreadId is declared as a HANDLE,
    /// it is indeed the thread ID as suggested by its name.
    /// It is picked up from the UniqueThread member of the CLIENT_ID in the
    /// TEB of the thread that asks to terminate the process.
    ShutdownThreadId: HANDLE,
};

/// Microsoft documentation of this is incomplete, the fields here are taken from various resources including:
///  - https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
///  - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Reserved5: [3]PVOID,
    DUMMYUNIONNAME: extern union {
        CheckSum: ULONG,
        Reserved6: PVOID,
    },
    TimeDateStamp: ULONG,
};

pub const M128A = extern struct {
    Low: ULONGLONG,
    High: LONGLONG,
};

pub const XMM_SAVE_AREA32 = extern struct {
    ControlWord: WORD,
    StatusWord: WORD,
    TagWord: BYTE,
    Reserved1: BYTE,
    ErrorOpcode: WORD,
    ErrorOffset: DWORD,
    ErrorSelector: WORD,
    Reserved2: WORD,
    DataOffset: DWORD,
    DataSelector: WORD,
    Reserved3: WORD,
    MxCsr: DWORD,
    MxCsr_Mask: DWORD,
    FloatRegisters: [8]M128A,
    XmmRegisters: [16]M128A,
    Reserved4: [96]BYTE,
};

pub const CONTEXT = extern struct {
    P1Home: DWORD64 align(16),
    P2Home: DWORD64,
    P3Home: DWORD64,
    P4Home: DWORD64,
    P5Home: DWORD64,
    P6Home: DWORD64,
    ContextFlags: DWORD,
    MxCsr: DWORD,
    SegCs: WORD,
    SegDs: WORD,
    SegEs: WORD,
    SegFs: WORD,
    SegGs: WORD,
    SegSs: WORD,
    EFlags: DWORD,
    Dr0: DWORD64,
    Dr1: DWORD64,
    Dr2: DWORD64,
    Dr3: DWORD64,
    Dr6: DWORD64,
    Dr7: DWORD64,
    Rax: DWORD64,
    Rcx: DWORD64,
    Rdx: DWORD64,
    Rbx: DWORD64,
    Rsp: DWORD64,
    Rbp: DWORD64,
    Rsi: DWORD64,
    Rdi: DWORD64,
    R8: DWORD64,
    R9: DWORD64,
    R10: DWORD64,
    R11: DWORD64,
    R12: DWORD64,
    R13: DWORD64,
    R14: DWORD64,
    R15: DWORD64,
    Rip: DWORD64,
    DUMMYUNIONNAME: extern union {
        FltSave: XMM_SAVE_AREA32,
        FloatSave: XMM_SAVE_AREA32,
        DUMMYSTRUCTNAME: extern struct {
            Header: [2]M128A,
            Legacy: [8]M128A,
            Xmm0: M128A,
            Xmm1: M128A,
            Xmm2: M128A,
            Xmm3: M128A,
            Xmm4: M128A,
            Xmm5: M128A,
            Xmm6: M128A,
            Xmm7: M128A,
            Xmm8: M128A,
            Xmm9: M128A,
            Xmm10: M128A,
            Xmm11: M128A,
            Xmm12: M128A,
            Xmm13: M128A,
            Xmm14: M128A,
            Xmm15: M128A,
        },
    },
    VectorRegister: [26]M128A,
    VectorControl: DWORD64,
    DebugControl: DWORD64,
    LastBranchToRip: DWORD64,
    LastBranchFromRip: DWORD64,
    LastExceptionToRip: DWORD64,
    LastExceptionFromRip: DWORD64,

    pub fn getRegs(ctx: *const CONTEXT) struct { bp: usize, ip: usize, sp: usize } {
        return .{ .bp = ctx.Rbp, .ip = ctx.Rip, .sp = ctx.Rsp };
    }

    pub fn setIp(ctx: *CONTEXT, ip: usize) void {
        ctx.Rip = ip;
    }

    pub fn setSp(ctx: *CONTEXT, sp: usize) void {
        ctx.Rsp = sp;
    }
};

pub const MAX_WOW64_SHARED_ENTRIES = 16;
pub const PROCESSOR_FEATURE_MAX = 64;
pub const MAXIMUM_XSTATE_FEATURES = 64;

pub const KSYSTEM_TIME = extern struct {
    LowPart: ULONG,
    High1Time: LONG,
    High2Time: LONG,
};

pub const NT_PRODUCT_TYPE = enum(INT) {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer,
};

pub const ALTERNATIVE_ARCHITECTURE_TYPE = enum(INT) {
    StandardDesign,
    NEC98x86,
    EndAlternatives,
};

pub const XSTATE_FEATURE = extern struct {
    Offset: ULONG,
    Size: ULONG,
};

pub const XSTATE_CONFIGURATION = extern struct {
    EnabledFeatures: ULONG64,
    Size: ULONG,
    OptimizedSave: ULONG,
    Features: [MAXIMUM_XSTATE_FEATURES]XSTATE_FEATURE,
};

/// Shared Kernel User Data
pub const KUSER_SHARED_DATA = extern struct {
    TickCountLowDeprecated: ULONG,
    TickCountMultiplier: ULONG,
    InterruptTime: KSYSTEM_TIME,
    SystemTime: KSYSTEM_TIME,
    TimeZoneBias: KSYSTEM_TIME,
    ImageNumberLow: USHORT,
    ImageNumberHigh: USHORT,
    NtSystemRoot: [260]WCHAR,
    MaxStackTraceDepth: ULONG,
    CryptoExponent: ULONG,
    TimeZoneId: ULONG,
    LargePageMinimum: ULONG,
    AitSamplingValue: ULONG,
    AppCompatFlag: ULONG,
    RNGSeedVersion: ULONGLONG,
    GlobalValidationRunlevel: ULONG,
    TimeZoneBiasStamp: LONG,
    NtBuildNumber: ULONG,
    NtProductType: NT_PRODUCT_TYPE,
    ProductTypeIsValid: BOOLEAN,
    Reserved0: [1]BOOLEAN,
    NativeProcessorArchitecture: USHORT,
    NtMajorVersion: ULONG,
    NtMinorVersion: ULONG,
    ProcessorFeatures: [PROCESSOR_FEATURE_MAX]BOOLEAN,
    Reserved1: ULONG,
    Reserved3: ULONG,
    TimeSlip: ULONG,
    AlternativeArchitecture: ALTERNATIVE_ARCHITECTURE_TYPE,
    BootId: ULONG,
    SystemExpirationDate: LARGE_INTEGER,
    SuiteMaskY: ULONG,
    KdDebuggerEnabled: BOOLEAN,
    DummyUnion1: extern union {
        MitigationPolicies: UCHAR,
        Alt: packed struct {
            NXSupportPolicy: u2,
            SEHValidationPolicy: u2,
            CurDirDevicesSkippedForDlls: u2,
            Reserved: u2,
        },
    },
    CyclesPerYield: USHORT,
    ActiveConsoleId: ULONG,
    DismountCount: ULONG,
    ComPlusPackage: ULONG,
    LastSystemRITEventTickCount: ULONG,
    NumberOfPhysicalPages: ULONG,
    SafeBootMode: BOOLEAN,
    DummyUnion2: extern union {
        VirtualizationFlags: UCHAR,
        Alt: packed struct {
            ArchStartedInEl2: u1,
            QcSlIsSupported: u1,
            SpareBits: u6,
        },
    },
    Reserved12: [2]UCHAR,
    DummyUnion3: extern union {
        SharedDataFlags: ULONG,
        Alt: packed struct {
            DbgErrorPortPresent: u1,
            DbgElevationEnabled: u1,
            DbgVirtEnabled: u1,
            DbgInstallerDetectEnabled: u1,
            DbgLkgEnabled: u1,
            DbgDynProcessorEnabled: u1,
            DbgConsoleBrokerEnabled: u1,
            DbgSecureBootEnabled: u1,
            DbgMultiSessionSku: u1,
            DbgMultiUsersInSessionSku: u1,
            DbgStateSeparationEnabled: u1,
            SpareBits: u21,
        },
    },
    DataFlagsPad: [1]ULONG,
    TestRetInstruction: ULONGLONG,
    QpcFrequency: LONGLONG,
    SystemCall: ULONG,
    Reserved2: ULONG,
    SystemCallPad: [2]ULONGLONG,
    DummyUnion4: extern union {
        TickCount: KSYSTEM_TIME,
        TickCountQuad: ULONG64,
        Alt: extern struct {
            ReservedTickCountOverlay: [3]ULONG,
            TickCountPad: [1]ULONG,
        },
    },
    Cookie: ULONG,
    CookiePad: [1]ULONG,
    ConsoleSessionForegroundProcessId: LONGLONG,
    TimeUpdateLock: ULONGLONG,
    BaselineSystemTimeQpc: ULONGLONG,
    BaselineInterruptTimeQpc: ULONGLONG,
    QpcSystemTimeIncrement: ULONGLONG,
    QpcInterruptTimeIncrement: ULONGLONG,
    QpcSystemTimeIncrementShift: UCHAR,
    QpcInterruptTimeIncrementShift: UCHAR,
    UnparkedProcessorCount: USHORT,
    EnclaveFeatureMask: [4]ULONG,
    TelemetryCoverageRound: ULONG,
    UserModeGlobalLogger: [16]USHORT,
    ImageFileExecutionOptions: ULONG,
    LangGenerationCount: ULONG,
    Reserved4: ULONGLONG,
    InterruptTimeBias: ULONGLONG,
    QpcBias: ULONGLONG,
    ActiveProcessorCount: ULONG,
    ActiveGroupCount: UCHAR,
    Reserved9: UCHAR,
    DummyUnion5: extern union {
        QpcData: USHORT,
        Alt: extern struct {
            QpcBypassEnabled: UCHAR,
            QpcShift: UCHAR,
        },
    },
    TimeZoneBiasEffectiveStart: LARGE_INTEGER,
    TimeZoneBiasEffectiveEnd: LARGE_INTEGER,
    XState: XSTATE_CONFIGURATION,
    FeatureConfigurationChangeStamp: KSYSTEM_TIME,
    Spare: ULONG,
    UserPointerAuthMask: ULONG64,
};

/// Read-only user-mode address for the shared data.
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
/// https://msrc-blog.microsoft.com/2022/04/05/randomizing-the-kuser_shared_data-structure-on-windows/
pub const SharedUserData: *const KUSER_SHARED_DATA = @as(*const KUSER_SHARED_DATA, @ptrFromInt(0x7FFE0000));

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

extern "kernel32" fn VirtualAllocEx(
    hProcess: HANDLE,
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: DWORD,
    flProtect: DWORD,
) callconv(WINAPI) ?*anyopaque;

extern "kernel32" fn WriteProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: *anyopaque,
    lpBuffer: [*]const u8,
    nSize: usize,
    lpNumberOfBytesWritten: ?*usize,
) callconv(WINAPI) BOOL;

extern "kernel32" fn CreateRemoteThread(
    hProcess: HANDLE,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) callconv(WINAPI) ?HANDLE;

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

pub extern "kernel32" fn GetHandleInformation(
    hObject: HANDLE,
    lpdwFlags: *DWORD,
) callconv(WINAPI) BOOL;

pub extern "kernel32" fn GetProcessId(
    Process: HANDLE,
) callconv(WINAPI) DWORD;

// CreateCustomProcess creates a new process in a custom state.
// IN : dwCreationFlags - Creation flags for the process.
//      lpProcessName - The name/path of the process to create.
// OUT: dwProcessId - A pointer to receive the process ID.
//      hProcess - A pointer to receive the process handle.
//      hThread - A pointer to receive the main thread handle.
// RETURNS: true if the process was created successfully, false otherwise.
pub fn CreateCustomProcess(dwCreationFlags: DWORD, lpProcessName: ?LPWSTR, dwProcessId: *u32, hProcess: *HANDLE, hThread: *HANDLE) bool {

    // Initialize structs
    var startup_info: STARTUPINFOW = std.mem.zeroes(STARTUPINFOW);
    var process_info: PROCESS_INFORMATION = std.mem.zeroes(PROCESS_INFORMATION);

    const result: BOOL = CreateProcessW(
        null,
        lpProcessName,
        null,
        null,
        FALSE,
        dwCreationFlags, // Use the manually defined constant
        null,
        null,
        &startup_info,
        &process_info,
    );
    if (result == FALSE) {
        std.debug.print("[+] CreateProcessW() failed.\n", .{});
        return false;
    }

    std.debug.print("[+] DONE\n", .{});

    // Populate the output parameters
    dwProcessId.* = process_info.dwProcessId;
    hProcess.* = process_info.hProcess;
    hThread.* = process_info.hThread;

    return true;
}

// GetRemoteProcessId retrieves the process ID of a remote process by its name.
// IN : szProcessName - The name of the process to find.
// RETURNS: The process ID if found, or an error if the process was not found.
pub fn GetRemoteProcessId(szProcessName: []const u8) anyerror!DWORD {
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
    if (loop == FALSE) {
        return error.ProcessNotFound;
    }

    while (loop == TRUE) : (loop = Process32Next(snapshot, &process_entry)) {
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

// GetRemoteProcessHandle retrieves a handle to a remote process by its name.
// IN : szProcessName - The name of the process to find.
// OUT: dwProcessId - A pointer to a variable that will receive the process ID.
//      pProcess - A pointer to a HANDLE that will receive the process handle.
// RETURNS: true if the process was found and the handle was retrieved, false otherwise.

pub fn GetRemoteProcessHandle(szProcessName: []const u8, dwProcessId: *u32, pProcess: *HANDLE) bool {
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
    if (loop == FALSE) {
        std.debug.print("[-] Process32FirstW() failed.\n", .{});
        return false;
    }

    while (loop == TRUE) : (loop = Process32Next(snapshot, &process_entry)) {
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

//

// GetPEB retrieves a pointer to the Process Environment Block (PEB) of the current process.
// RETURNS: A pointer to the current process's PEB structure.
pub fn GetPEB() *win.PEB {
    return asm volatile (
        \\ movq %%gs:0x60, %[result]
        : [result] "=r" (-> *PEB),
    );
}

// GetTEB retrieves a pointer to the Thread Environment Block (TEB) of the current thread.
// RETURNS: A pointer to the current thread's TEB structure.
pub fn GetTEB() *TEB {
    return asm volatile (
        \\ movq %%gs:0x30, %[result]
        : [result] "=r" (-> *TEB),
    );
}

// ComptimeWS converts a UTF-8 string to a UTF-16 wide string at compile time.
// IN : str - The UTF-8 string to convert.
// RETURNS: A UTF-16 wide string representation of the input string.
// convert the string to a wide string UTF16-L in comptime
pub fn ComptimeWS(comptime str: []const u8) []const u16 {
    @setEvalBranchQuota(100_000_000);
    comptime {
        var wide_str = std.unicode.utf8ToUtf16LeStringLiteral(str);
        _ = &wide_str; // ignore
        return wide_str;
    }
}

// traverseLoadedDLLs enumerates and prints all loaded DLLs in the current process.
// This function walks through the InLoadOrderModuleList to display module information.
// RETURNS: void or an error if memory allocation or string conversion fails.
pub fn traverseLoadedDLLs() !void {
    const peb = std.os.windows.peb();

    var buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;
    while (true) {
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        if (mod_name_length == 0) break;

        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer[0..mod_name_length]);
        std.debug.print("{s}: {}\n", .{ mod_name_utf8, loaded_module.DllBase });
        alloc.free(mod_name_utf8);
        modules_linked_list = modules_linked_list.Flink;
    }
}

// HashString computes a hash value for a given string using the djb2 algorithm.
// IN : s - The string to hash.
// RETURNS: A 64-bit hash value of the input string.
pub fn HashString(s: []const u8) u64 {
    var hash: u64 = 5381;
    for (s) |d| {
        // We must use @addWithOverflow and @shlWithOverflow, as Zig would declare comptime error because of the overflow
        // The builtins return tuples with two values - the result in [0] and overflow bit in [1]
        hash = @addWithOverflow(@shlWithOverflow(hash, 5)[0], hash + std.ascii.toUpper(d))[0];
    }
    return hash;
}

// getModuleHandleHash retrieves a module handle by comparing hash values of module names.
// IN : moduleName - The name of the module to find (compared using hash).
// RETURNS: A handle to the module if found, null if not found, or an error.
pub fn getModuleHandleHash(comptime moduleName: []const u8) !?HINSTANCE {
    // We compute the hash of the searched module at compile time using the comptime keyword

    const moduleHash = comptime HashString(moduleName);
    // From here, the function is the same as previous example
    const peb = std.os.windows.peb();

    var buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;
    while (true) {
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        if (mod_name_length == 0) break;

        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer.?[0..mod_name_length]);
        // Instead of prtinting, we try if the hash matches with the searched hash
        if (HashString(mod_name_utf8) == moduleHash) {
            return @ptrCast(loaded_module.DllBase);
        }
        alloc.free(mod_name_utf8);
        modules_linked_list = modules_linked_list.Flink;
    }
    std.debug.print("Module not found in loaded DLLs.\n", .{});
    return null;
}

// getModuleHandle retrieves a module handle by comparing module names directly.
// IN : moduleName - The name of the module to find (exact string comparison).
// RETURNS: A handle to the module if found, null if not found, or an error.
pub fn getModuleHandle(comptime moduleName: []const u8) !?HINSTANCE {
    // We compute the hash of the searched module at compile time using the comptime keyword

    // From here, the function is the same as previous example
    const peb = std.os.windows.peb();

    var buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;
    while (true) {
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        if (mod_name_length == 0) break;

        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer[0..mod_name_length]);
        // Instead of printing, we try if the hash matches with the searched hash
        if (std.mem.eql(u8, mod_name_utf8, moduleName)) {
            return @ptrCast(loaded_module.DllBase);
        }
        alloc.free(mod_name_utf8);
        modules_linked_list = modules_linked_list.Flink;
    }
    std.debug.print("Module not found in loaded DLLs.\n", .{});
    return null;
}

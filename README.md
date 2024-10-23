# Offensive Zig

This repo contains code snippets from exploring usage of Zig in malware development.

## Description

**Suspended Process Injection**
- Create a process in suspended state
- Allocate memory in the process
- CreateRemoteThread to execute the payload

**Get Remote Process**
- Zig can't return multiple values/objects from a function, so the function returns a process struct with the ID and Handle
- Takes in a constant utf8 array ([]const u8) and returns a ProcessIdentifier struct with:
    - processId: win.DWORD
    - handle: win.HANDLE
- Converts the input to lowercase and all enumerated processes to lowercase
- Due to Zig string handling (no null-terminated strings), the process names all have trailing 0s that need to be removed, so we cast to a pointer and create a slice the size of the process name we're looking for.
- Attempts to use OpenProcess when the process is found and retrieve a handle
- Populate and return the struct

**Utility**
- Contains general functions that may be useful when interacting with Windows or developing malware

## Using System Libraries

There are some Windows functions that are not implemented in the std.os.windows library, ie. you cannot call them directly with Zig.  This was the issue I was facing when trying to make a GetRemoteProcess function, the CreateToolhelp32Snapshot is not implemented. Therefore we need to import library with C and use the function that way. To do this import the functions in your code like so:
```
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});
```
Then inside your build.zig you need to link the executable to the libraries (libc):
```
const exe = b.addExecutable(.{
        .name = "GetRemoteProcess",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    exe.linkLibC();
    exe.linkSystemLibrary("kernel32");
    exe.linkSystemLibrary("user32");
```

This can also be accomplished with the `-lc` command line argument.

## Building a Windows DLL

```
const std = @import("std");
const win = std.os.windows;

const WINAPI = win.WINAPI;
const HINSTANCE = win.HINSTANCE;
const DWORD = win.DWORD;
const LPVOID = win.LPVOID;
const BOOL = win.BOOL;
const HWND = win.HWND;
const LPCSTR = win.LPCSTR;
const UINT = win.UINT;

const DLL_PROCESS_DETACH: DWORD = 0;
const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_THREAD_ATTACH: DWORD = 2;
const DLL_THREAD_DETACH: DWORD = 3;


extern "user32" fn MessageBoxA(hWnd: ?HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT) callconv(WINAPI) i32;

pub export fn _DllMainCRTStartup(hinstDLL: HINSTANCE, fdwReason: DWORD, lpReserved: LPVOID) BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            _ = MessageBoxA(null, "Hello World!", "Zig", 0);
        },
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        DLL_PROCESS_DETACH => {},
        else => {},
    }
    return 1;
}
```

To compile:
```
//To make a static library
zig build-lib test.zig -target x86_64-windows 
//To make a shared library
zig build-lib test.zig -dynamic -target x86_64-windows 
```

## Build Options

### Default

Some CPU architectures that you can cross-compile for:
- x86_64
- arm
- aarch64
- i386
- riscv64
- wasm32

Some operating systems you can cross-compile for:
- linux
- macos
- windows
- freebsd
- netbsd
- dragonfly
- UEFI

Optimization Options:
- `-D optimize=Debug`
    - Optimizations off and safety on (default)
- `-D optimize=ReleaseSafe`
    - Optimizations on and safety on
- `-D optimize=ReleaseFast`
    - Optimizations on and safety off
- `-D optimize=ReleaseSmall`
    - Size optimizations on and safety off

`-f strip` removes debug information from the binary

Interestingly they have an option `-f pie` which produces a Position Independent Executable - I haven't tested this yet.

See more options here: https://github.com/ziglang/zig/blob/master/build.zig

### Custom

We can also add our own build options, and instruct the compiler on how to compile the binary within the code. This can give us some flexible options when building implants / loaders for example. 
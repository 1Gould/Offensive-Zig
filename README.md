# Offensive Zig

This repo contains code snippets from exploring usage of Zig in malware development.

Inspired by:
- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)
- [Rust-For-Malware-Development](https://github.com/Whitecat18/Rust-for-Malware-Development)
- [OffensiveRust](https://github.com/trickster0/OffensiveRust)
- [OffensiveCpp](https://github.com/lsecqt/OffensiveCpp)

## Table of Contents

- [Offensive Zig](#offensive-zig)
  - [Table of Contents](#table-of-contents)
  - [Why Zig?](#why-zig)
  - [Examples in this project](#description)
  - [Using System Libraries](#using-system-libraries)
  - [Building a Windows DLL](#building-a-windows-dll)
  - [Build Options](#build-options)
  - [References](#references)

## Why Zig?

- Flexible build / compilation options allow for us to cross-compile including C/C++ compatability.
- Various options to reduce executable size and increase performance.
- Interoperable with existing C/C++ toolchain.
- Low level with memory manipulation, can also interface with inline assembly.
- Challenge your programming skills (it's not for the easily frustrated).

## Description

**Suspended Process Injection**
- Create a process in suspended state
- Allocate memory in the process
- CreateRemoteThread to execute the payload

**Utility**
- Contains general functions that may be useful when interacting with Windows or developing malware
- GetRemoteProcessHandle & GetRemoteProcessId
- GetRemoteProcessHandleW & GetRemoteProcessIdW
- GetPEB() & GetTEB() using asm

## Using System Libraries

There are some Windows functions that are not implemented in the std.os.windows library, ie. you cannot call them directly with Zig.  This was the issue I was facing when trying to make a GetRemoteProcess function, the CreateToolhelp32Snapshot is not implemented. Therefore we need to import library with C and use the function that way. To do this import the functions in your code like so:
```zig
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
});
```
Then inside your build.zig you need to link the executable to the libraries (libc):
```zig
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

```zig
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

### OPSEC

Optimization Options:
- `-Doptimize=Debug`
    - Optimizations off and safety on (default)
- `-Doptimize=ReleaseSafe`
    - Optimizations on and safety on
- `-Doptimize=ReleaseFast`
    - Optimizations on and safety off
- `-Doptimize=ReleaseSmall`
    - Size optimizations on and safety off

For compiling these options are recommended for OPSEC:
```
zig build-exe test.zig -Doptimize=ReleaseSmall
```

Stripping debug information is done with the strip option in build.zig.
```zig
    const exe = b.addExecutable(.{
        .name = "ApiHashing",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
//      .singlethreaded = true,
    });
```

See more options here: https://github.com/ziglang/zig/blob/master/build.zig

An interesting option pie (Position Independent Executable) exists here: https://github.com/ziglang/zig/blob/e9220525e836810425e925722d1beaba9bfe9d91/build.zig#L179

### Custom

We can also add our own build options, and instruct the compiler on how to compile the binary within the code. This can give us some flexible options when building implants / loaders for example. 

## API Hashing

Zig has the comptime keyword which can be used to get the hash at compile time. Not exactly the same implementation as C++ with the __TIME__ macro, external libraries cannot be called at compile time. Therefore in the build.zig file we can generate std.time.timestamp() as a file and embed it with @embedFile()to calculate the hash at compile time.


## References

Here are some references to help you get started:

- https://github.com/darkr4y/OffensiveZig
- https://github.com/0xsp-SRD/ZigStrike
- https://github.com/michal-sladecek/zig_experiments
- https://github.com/GoNZooo/zig-win32
- https://github.com/Sobeston/injector
# Zig-Snippets

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


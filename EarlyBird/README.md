# EarlyBird - APC Injection Implementation in Zig

## Overview

EarlyBird is an educational implementation of the **Early Bird APC (Asynchronous Procedure Call) Injection** technique written in Zig for Windows systems. This project demonstrates a code injection method that leverages Windows' APC mechanism to execute shellcode in a target process.


## What is APC Injection?

APC (Asynchronous Procedure Call) injection is a code injection technique that takes advantage of Windows' APC mechanism. The Early Bird variant works by:

1. Creating a target process in a suspended state
2. Allocating memory within the target process
3. Writing shellcode to the allocated memory region
4. Modifying memory permissions to make the region executable
5. Queuing an APC that points to the shellcode
6. Resuming the main thread, which triggers APC execution

## Technical Implementation

### Core Components

- **Process Creation**: Uses `CreateProcessW` with `CREATE_SUSPENDED` or `DEBUG_PROCESS` flags
- **Memory Allocation**: Leverages `VirtualAllocEx` for remote memory allocation
- **Memory Writing**: Utilizes `WriteProcessMemory` to inject shellcode
- **Permission Changes**: Employs `VirtualProtectEx` to make memory executable
- **APC Queuing**: Uses `QueueUserAPC` to schedule shellcode execution
- **Thread Management**: Controls thread execution with `ResumeThread`

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   EarlyBird     │───▶│  Target Process  │───▶│   Shellcode     │
│   (Injector)    │    │   (Suspended)    │    │   Execution     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
    Create Process    ──▶   Allocate Memory   ──▶   Queue APC
         │                       │                       │
         ▼                       ▼                       ▼
    Write Shellcode   ──▶   Change Permissions ──▶  Resume Thread
```

## Building the Project


### Build Commands

**Combined options:**
```bash
zig build run -Dprocessname=calc.exe -Dcreateprocess=suspended
```

### Build Options

| Option | Description | Default | Values |
|--------|-------------|---------|---------|
| `processname` | Target process executable name | `notepad.exe` | Any valid executable name |
| `createprocess` | Process creation method | `debug` | `suspended`, `debug` |

## Usage Examples

### Example 1: Basic Execution
```bash
# Inject into notepad.exe using debug mode
zig build run
```

### Example 2: Custom Target
```bash
# Inject into calc.exe using suspended mode
zig build run -Dprocessname=calc.exe -Dcreateprocess=suspended
```

## References

- [Microsoft Documentation - Asynchronous Procedure Calls](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)
- [MITRE ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Windows Internals - Process and Thread Management](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)


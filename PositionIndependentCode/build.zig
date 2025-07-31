const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // We will also create a module for our other entry point, 'main.zig'.
    const exe_mod = b.addExecutable(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .name = "PositionIndependentCode",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true, // Position Independent Code
        .strip = true, // Remove debug symbols
    });

    // Configure for shellcode generation
    exe_mod.entry = .{ .symbol_name = "shellcode" }; // Use our custom entry point
    exe_mod.root_module.addImport("win32", b.createModule(.{ .root_source_file = b.path("lib/zigwin32/win32.zig") }));

    // Disable stack protection and other features that might interfere with shellcode
    exe_mod.root_module.stack_check = false;
    exe_mod.root_module.stack_protector = false;

    b.installArtifact(exe_mod);

    // Add a step to extract the shellcode as a binary file
    // const extract_shellcode = b.addSystemCommand(&.{ "powershell", "-Command", "& { $exe = Get-Content 'zig-out/bin/PositionIndependentCode.exe' -Raw -Encoding Byte; " ++
    //     "$pe = [System.IO.File]::ReadAllBytes('zig-out/bin/PositionIndependentCode.exe'); " ++
    //     "$dosHeader = [System.BitConverter]::ToUInt32($pe, 0x3C); " ++
    //     "$ntHeader = $dosHeader + 4; " ++
    //     "$textSectionOffset = $ntHeader + 0x18 + 0xF0 + 0x28; " ++
    //     "$textRVA = [System.BitConverter]::ToUInt32($pe, $textSectionOffset + 0x0C); " ++
    //     "$textSize = [System.BitConverter]::ToUInt32($pe, $textSectionOffset + 0x08); " ++
    //     "$textFileOffset = [System.BitConverter]::ToUInt32($pe, $textSectionOffset + 0x14); " ++
    //     "$shellcode = $pe[$textFileOffset..($textFileOffset + $textSize - 1)]; " ++
    //     "[System.IO.File]::WriteAllBytes('zig-out/bin/shellcode.bin', $shellcode); " ++
    //     "Write-Host 'Shellcode extracted to zig-out/bin/shellcode.bin' }" });
    // extract_shellcode.step.dependOn(b.getInstallStep());

    // const extract_step = b.step("extract", "Extract shellcode as binary file");
    // extract_step.dependOn(&extract_shellcode.step);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe_mod);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}

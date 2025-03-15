const std = @import("std");
const print = std.debug.print;
const assert = std.debug.assert;

const InstallerError = error{
    DownloadFailed,
    InvalidResponse,
    UnsupportedPlatform,
    TarballNotFound,
    InvalidSignatureFormat,
    VerificationFailed,
};

const MINISIGN_KEY = "RWR+9B91GBZ0zOjh6Lr17+zKf5BoSuFvrx2xSeDE57uIYvnKBGmMjOex";

fn STOP_HERE() unreachable {
    print("Breakpoint here");
    assert(false); 
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();
    var stdout = std.io.getStdOut().writer();

    const zigVersion = try getZigVersion();
    print("Current zig version: {s}\n", .{zigVersion});

    STOP_HERE();
    
    // Build the API URL for version selection.
    const apiUrl = try std.fmt.allocPrint(allocator,
        "https://releases.zigtools.org/v1/zls/select-version?zig_version={}&compatibility=only-runtime",
        .{versionArg});
    std.debug.print("Fetching version info from: {s}\n", .{apiUrl});

    // Download JSON metadata.
    const jsonData = try download(apiUrl);
    // Parse the JSON to get the tarball URL.
    const tarballUrl = try parseTarballUrl(jsonData);
    std.debug.print("Tarball URL: {s}\n", .{tarballUrl});

    // Download the tarball.
    const tarballData = try download(tarballUrl);
    // Download the minisig file (assumes URL is the tarball URL plus ".minisig")
    const sigUrl = try std.fmt.allocPrint(allocator, "{s}.minisig", .{tarballUrl});
    std.debug.print("Fetching minisig from: {s}\n", .{sigUrl});
    const sigText = try downloadText(sigUrl);

    // Verify the downloaded tarball using minisign.
    try minisignVerify(MINISIGN_KEY, tarballData, sigText);
    std.debug.print("Minisign verification succeeded.\n", .{});

    // Write tarball to disk.
    const tarballPath = "zls.tar.gz";
    try std.fs.cwd().writeFile(tarballPath, tarballData);
    std.debug.print("Saved tarball to: {s}\n", .{tarballPath});

    // Extract the tarball to the installation directory.
    const installDir = "zls_install";
    try extractTarball(tarballPath, installDir, 1);
    std.debug.print("Extracted tarball to: {s}\n", .{installDir});

    // On Unix, create a symlink for the binary inside a "bin" folder.
    if (std.os.tag == .Unix) {
        const binDir = std.fs.path.join(installDir, "bin");
        try std.fs.cwd().createDirAll(binDir, .{});
        // Create a relative symlink: bin/zls -> ../zls
        const target = std.fs.path.join("..", "zls");
        const linkPath = std.fs.path.join(binDir, "zls");
        try std.fs.cwd().symlink(target, linkPath);
        std.debug.print("Created symlink at: {s}\n", .{linkPath});
    }

    std.debug.print("Installed zls successfully.\n", .{});
}

/// Run the "zig version" command and return current version
fn getZigVersion(alc: std.mem.Allocator) ![]const u8 {
    var childProcess = try std.ChildProcess.init(.{
        .argv = &[_][]const u8{"zig", "version"},
    });

    defer childProcess.deinit();
    try childProcess.spawn();

    var output = try childProcess.readAllStdOutAlloc(alc);
    try childProcess.wait();

    return std.mem.trim(u8, output, " \t\r\n");
}

/// Download binary data from the given URL.
/// (For simplicity, this uses a minimal HTTP GET implementation from std.http.)
fn download(url: []const u8) ![]u8 {
    const allocator = std.heap.page_allocator;
    var client = try std.http.Client.init(allocator);
    defer client.deinit();
    var response = try client.get(url, 5000);
    if (response.status != 200) return InstallerError.DownloadFailed;
    return response.body;
}

/// Download text (UTF-8) data from a URL.
fn downloadText(url: []const u8) ![]const u8 {
    return try download(url); // assuming the returned data is valid UTF-8
}

/// Parse the JSON metadata and return the tarball URL.
/// The JSON is expected to have an object with keys in the form "os-arch" (for example, "linux-x86_64")
/// and a nested object containing the "tarball" URL.
fn parseTarballUrl(jsonData: []u8) ![]const u8 {
    const allocator = std.heap.page_allocator;
    var parser = std.json.Parser.init(jsonData, allocator);
    const value = try parser.parse();
    // If the API returned an error (a "code" field), then bail.
    if (value.getObject().?["code"] != null) {
        return InstallerError.InvalidResponse;
    }
    // Build key from OS and architecture.
    const osKey = try std.fmt.allocPrint(allocator, "{s}-{s}", .{ getOS(), getArch() });
    const obj = value.getObject().?;
    const platform = obj[osKey] orelse return InstallerError.UnsupportedPlatform;
    const tarball = platform.getObject()?["tarball"] orelse return InstallerError.TarballNotFound;
    return tarball.String?;
}

/// Returns a string representing the OS.
/// (Currently supports "macos", "linux", "freebsd"; otherwise returns "unknown".)
fn getOS() []const u8 {
    if (std.os.tag == .MacOS) return "macos";
    else if (std.os.tag == .Linux) return "linux";
    else if (std.os.tag == .FreeBSD) return "freebsd";
    else return "unknown";
}

/// Returns a string representing the CPU architecture.
/// (Supports "x86_64", "aarch64", "armv7a", "riscv64"; otherwise returns "unknown".)
fn getArch() []const u8 {
    const arch = std.builtin.cpu.arch;
    if (arch == .x86_64) return "x86_64";
    else if (arch == .aarch64) return "aarch64";
    else if (arch == .arm) return "armv7a";
    else if (arch == .riscv64) return "riscv64";
    else return "unknown";
}

/// Verify the given data with the provided minisign signature and public key.
/// This simplified implementation:
/// - Decodes the public key from base64,
/// - Extracts the first non-empty line from the signature text (assumed to be base64 encoded),
/// - And then verifies the data using Zig’s ed25519 implementation.
fn minisignVerify(pubKeyStr: []const u8, data: []const u8, sigText: []const u8) !void {
    const allocator = std.heap.page_allocator;
    const pubKey = try std.base64.decodeAlloc(u8, pubKeyStr, allocator);
    // Get the first non-empty line from the signature text.
    var sigLine: []const u8 = "";
    var it = std.mem.split(sigText, "\n");
    while (it.next()) |line| {
        if (!std.mem.isEmpty(line)) {
            sigLine = line;
            break;
        }
    }
    if (std.mem.isEmpty(sigLine)) return InstallerError.InvalidSignatureFormat;
    const signature = try std.base64.decodeAlloc(u8, sigLine, allocator);
    if (!std.crypto.ed25519.verify(pubKey, data, signature)) {
        return InstallerError.VerificationFailed;
    }
}

/// Extract a gzip-compressed tar archive to the destination directory.
/// This minimal tar extractor only supports regular files and directories in the ustar format,
/// and it applies `stripComponents` (i.e. it removes that many leading path components).
fn extractTarball(tarballPath: []const u8, destDir: []const u8, stripComponents: u8) !void {
    const fs = std.fs;
    const allocator = std.heap.page_allocator;
    var file = try fs.cwd().openFile(tarballPath, .{ .read = true });
    defer file.close();
    const fileData = try file.readToEndAlloc(allocator, 8192);

    // Decompress gzip data.
    var decompressor = std.compress.gzip.Decompressor.init(fileData);
    const tarData = try decompressor.decompress();

    var pos: usize = 0;
    while (pos + 512 <= tarData.len) {
        const header = tarData[pos .. pos + 512];
        // A header block full of zeros indicates the end of the archive.
        if (std.mem.allEqual(u8, header, 0)) break;

        // Read file name from header (bytes 0-99) and trim nulls.
        const nameField = header[0 .. 100];
        var fileName = std.mem.trim(u8, nameField, "\0");
        // Remove the configured number of leading path components.
        fileName = stripPath(fileName, stripComponents);
        if (fileName.len == 0) {
            pos += 512;
            continue;
        }

        // Read file size from header (bytes 124-135, in octal).
        const sizeField = header[124 .. 136];
        const sizeStr = std.mem.trim(u8, sizeField, "\0 ");
        const fileSize = try std.fmt.parseInt(usize, sizeStr, 8);

        const fileTypeFlag = header[156];
        const destPath = fs.path.join(destDir, fileName);
        if (fileTypeFlag == '5') {
            // Directory entry.
            try fs.cwd().createDirAll(destPath, .{});
        } else if (fileTypeFlag == '0' or fileTypeFlag == '\0') {
            // Regular file.
            const parent = fs.path.dirname(destPath);
            try fs.cwd().createDirAll(parent, .{});
            var outFile = try fs.cwd().createFile(destPath, .{});
            try outFile.write(tarData[(pos + 512) .. (pos + 512 + fileSize)]);
            outFile.close();
        }
        // Advance position: header (512 bytes) + file data (padded to 512-byte blocks)
        pos += 512 + ((fileSize + 511) / 512) * 512;
    }
}

/// Helper: strip the first `count` "/"-separated components from a path.
fn stripPath(path: []const u8, count: u8) []const u8 {
    var remaining = path;
    var c: u8 = 0;
    while (c < count) : (c += 1) {
        const idx = std.mem.indexOf(u8, remaining, '/');
        if (idx) |i| {
            remaining = remaining[i + 1 ..];
        } else {
            return "";
        }
    }
    return remaining;
}

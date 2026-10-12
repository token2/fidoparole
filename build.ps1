<#
  build.ps1 - builds FidoParole (Tauri) on Windows x64 as a portable folder.

  FidoParole talks to keys over FIDO HID with upstream libfido2 (fido2.dll,
  USB HID only, built here). Windows only allows FIDO HID access to elevated
  programs, so run fidoparole.exe as administrator.

  Usage (PowerShell, from this folder):
      Set-ExecutionPolicy -Scope Process Bypass
      .\build.ps1                 # release, portable folder in .\dist\fidoparole
      .\build.ps1 -Dev            # debug build, run it
      .\build.ps1 -RebuildFido2   # force a fresh libfido2 build

  Prerequisites: Visual Studio 2022 C++ build tools, CMake, Git, Rust (MSVC toolchain).
  vcpkg is fetched automatically if missing. WebView2 ships with Windows 10/11.
#>
[CmdletBinding()]
param(
    [string]$VcpkgPath = "C:\vcpkg",
    [string]$LibFido2Tag = "1.15.0",
    [switch]$Dev,
    [switch]$RebuildFido2,
    [string]$DistPath = ""
)
$ErrorActionPreference = "Stop"
$Here  = $PSScriptRoot
$App   = Join-Path $Here "src-tauri"
$Root  = $Here
if ($DistPath) { $Dist = $DistPath } else { $Dist = Join-Path $Root "dist" }
$Portable = Join-Path $Dist "fidoparole"
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Need($cmd, $hint) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "'$cmd' not found. $hint" } }

Step "Checking prerequisites"
Need cmake "Install Visual Studio 2022 with the C++ workload, or CMake from cmake.org."
Need git   "Install Git for Windows."
Need cargo "Install Rust from https://rustup.rs (MSVC toolchain)."

Step "vcpkg dependencies (openssl, zlib, libcbor)"
if (-not (Test-Path "$VcpkgPath\vcpkg.exe")) {
    if (-not (Test-Path $VcpkgPath)) { git clone https://github.com/microsoft/vcpkg $VcpkgPath }
    & "$VcpkgPath\bootstrap-vcpkg.bat" -disableMetrics
}
& "$VcpkgPath\vcpkg.exe" install openssl:x64-windows zlib:x64-windows libcbor:x64-windows
if ($LASTEXITCODE) { throw "vcpkg install failed" }
$I = "$VcpkgPath\installed\x64-windows"

$Fido      = Join-Path $Root "deps\libfido2"
$FBuild    = Join-Path $Fido "build"
$FidoLibDir = Join-Path $FBuild "src\Release"

# Rebuild libfido2 when the build configuration changes (the marker records it).
$BuildSig = "libfido2 $LibFido2Tag upstream hid-only v2"
$Marker = Join-Path $FBuild ".vault-build"
$Stale = -not (Test-Path $Marker) -or ((Get-Content $Marker -Raw).Trim() -ne $BuildSig)
if ($RebuildFido2 -or $Stale -or -not (Test-Path "$FidoLibDir\fido2.lib")) {
    Step "Building libfido2 $LibFido2Tag (upstream, USB HID)"
    if (-not (Test-Path "$Fido\CMakeLists.txt")) {
        New-Item -ItemType Directory -Force (Join-Path $Root "deps") | Out-Null
        git clone --depth 1 --branch $LibFido2Tag https://github.com/Yubico/libfido2 $Fido
        if ($LASTEXITCODE) { throw "git clone of libfido2 failed" }
    }
    Push-Location $Fido
    git checkout -- . 2>$null
    git clean -fd -e build 2>$null
    Pop-Location
    $ZlibLib = @("zlib.lib", "z.lib") | ForEach-Object { Join-Path "$I\lib" $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ZlibLib) { throw "zlib.lib not found under $I\lib" }
    $ZlibName = [System.IO.Path]::GetFileNameWithoutExtension($ZlibLib)
    # A configure from an earlier failed run can hold stale cache entries.
    if (Test-Path "$FBuild\CMakeCache.txt") { Remove-Item -Force "$FBuild\CMakeCache.txt" }
    $fidoArgs = @(
        "-S", $Fido, "-B", $FBuild, "-A", "x64",
        "-DBUILD_TESTS=OFF", "-DBUILD_EXAMPLES=OFF", "-DBUILD_MANPAGES=OFF", "-DBUILD_TOOLS=OFF", "-DBUILD_STATIC_LIBS=OFF",
        "-DUSE_PCSC=OFF", "-DUSE_WINHELLO=OFF",
        "-DCBOR_INCLUDE_DIRS=$I\include", "-DCBOR_LIBRARY_DIRS=$I\lib", "-DCBOR_BIN_DIRS=$I\bin", "-DCBOR_LIBRARIES=cbor",
        "-DCRYPTO_INCLUDE_DIRS=$I\include", "-DCRYPTO_LIBRARY_DIRS=$I\lib", "-DCRYPTO_BIN_DIRS=$I\bin", "-DCRYPTO_LIBRARIES=libcrypto",
        # libfido2's MSVC branch requires the plural *_DIRS variables (and *_BIN_DIRS);
        # find_package(ZLIB) reads the singular ones. Pass both.
        "-DZLIB_INCLUDE_DIRS=$I\include", "-DZLIB_LIBRARY_DIRS=$I\lib", "-DZLIB_BIN_DIRS=$I\bin", "-DZLIB_LIBRARIES=$ZlibName",
        "-DZLIB_ROOT=$I", "-DZLIB_INCLUDE_DIR=$I\include", "-DZLIB_LIBRARY=$ZlibLib"
    )
    cmake @fidoArgs
    if ($LASTEXITCODE) { throw "libfido2 cmake configure failed" }
    cmake --build $FBuild --config Release
    if ($LASTEXITCODE) { throw "libfido2 build failed" }
    Set-Content -Path $Marker -Value $BuildSig -NoNewline
} else {
    Step "Reusing existing libfido2 build: $FidoLibDir\fido2.dll"
}
if (-not (Test-Path "$FidoLibDir\fido2.lib")) { throw "fido2.lib not produced in $FidoLibDir" }

# Runtime DLLs that must sit next to the exe.
$RuntimeDlls = @("$FidoLibDir\fido2.dll")
$RuntimeDlls += Get-ChildItem "$I\bin\cbor*.dll", "$I\bin\libcrypto*.dll", "$I\bin\zlib*.dll", "$I\bin\z.dll" -ErrorAction SilentlyContinue | ForEach-Object FullName

$env:FIDO2_LIB_DIR  = $FidoLibDir
$env:FIDO2_LIB_NAME = "fido2"
if ($env:CARGO_TARGET_DIR) { $Target = $env:CARGO_TARGET_DIR } else { $Target = "target" }

Push-Location $App
try {
    if ($Dev) {
        Step "Debug build"
        New-Item -ItemType Directory -Force "$Target\debug" | Out-Null
        $RuntimeDlls | ForEach-Object { Copy-Item $_ "$Target\debug\" -Force }
        cargo build
        if ($LASTEXITCODE) { throw "build failed" }
        & "$Target\debug\fidoparole.exe"
    } else {
        Step "Release build"
        cargo build --release
        if ($LASTEXITCODE) { throw "build failed" }
        New-Item -ItemType Directory -Force $Portable | Out-Null
        Copy-Item "$Target\release\fidoparole.exe" $Portable -Force
        $RuntimeDlls | ForEach-Object { Copy-Item $_ $Portable -Force }
        Write-Host "`nPortable build ready: $Portable" -ForegroundColor Green
        Write-Host "Run fidoparole.exe as administrator (right-click > Run as administrator): Windows only allows FIDO HID access to elevated programs."
    }
} finally { Pop-Location }

# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[CmdletBinding()]
param(
    [string[]]$Architecture = @('x64', 'arm64')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$rustup = Get-Command rustup -ErrorAction SilentlyContinue

if (-not $cargo) {
    $cargoPath = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $cargoPath) {
        $cargo = Get-Item -LiteralPath $cargoPath
    }
}
if (-not $rustup) {
    $rustupPath = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    if (Test-Path -LiteralPath $rustupPath) {
        $rustup = Get-Item -LiteralPath $rustupPath
    }
}
if (-not $cargo -or -not $rustup) {
    throw 'Rust is not installed. Install rustup before building.'
}

$targets = [ordered]@{
    x64   = 'x86_64-pc-windows-msvc'
    arm64 = 'aarch64-pc-windows-msvc'
}

$requested = foreach ($value in $Architecture) {
    foreach ($name in $value -split ',') {
        $normalized = $name.Trim().ToLowerInvariant()
        if (-not $targets.Contains($normalized)) {
            throw "Unsupported architecture '$name'. Use x64 or arm64."
        }
        $normalized
    }
}

Push-Location $repositoryRoot
try {
    foreach ($name in $requested | Select-Object -Unique) {
        $target = $targets[$name]
        & $rustup.FullName target add $target
        if ($LASTEXITCODE -ne 0) {
            throw "rustup target add failed for $target"
        }

        & $cargo.FullName build --locked --release --target $target -p refineid-minidriver
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed for $target"
        }

        $outputDirectory = Join-Path $repositoryRoot "dist\$name"
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
        $builtDll = Join-Path $repositoryRoot "target\$target\release\refineid_minidriver.dll"
        Copy-Item -LiteralPath $builtDll -Destination $outputDirectory -Force
    }

    $hashLines = foreach ($name in $requested | Select-Object -Unique) {
        $relativePath = "$name/refineid_minidriver.dll"
        $dll = Join-Path $repositoryRoot "dist\$relativePath"
        $hash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relativePath"
    }
    $hashLines | Set-Content -LiteralPath (Join-Path $repositoryRoot 'dist\SHA256SUMS') -Encoding ascii
} finally {
    Pop-Location
}

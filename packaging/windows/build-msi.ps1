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

<#
    .SYNOPSIS
    Builds the driver-only MSI for each requested architecture.

    .DESCRIPTION
    MSI packages are architecture-specific, so this produces one file per
    architecture rather than a single universal installer. Each package
    carries the matching release build of the Card Module DLL.

    The output is unsigned. Signing is a separate, later step; an unsigned
    package installs correctly but presents an unknown-publisher prompt.
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string[]]$Architecture = @('x64', 'arm64'),

    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot 'artifacts\msi'
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw 'The WiX toolset is required. Install it with: dotnet tool install --global wix'
}

# The MSI ProductVersion field is numeric, so take the three CalVer
# components from the workspace manifest rather than any suffix.
$manifest = Get-Content (Join-Path $repositoryRoot 'Cargo.toml') -Raw
if ($manifest -notmatch '(?m)^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
    throw 'Could not read the workspace version from Cargo.toml.'
}
$productVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"

$rustTargets = @{
    'x64'   = 'x86_64-pc-windows-msvc'
    'arm64' = 'aarch64-pc-windows-msvc'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

foreach ($arch in $Architecture) {
    $rustTarget = $rustTargets[$arch]
    Write-Host "Building refineid_minidriver.dll for $rustTarget"
    & cargo build --release --package refineid-minidriver --target $rustTarget
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed for $rustTarget."
    }

    $dll = Join-Path $repositoryRoot "target\$rustTarget\release\refineid_minidriver.dll"
    if (-not (Test-Path -LiteralPath $dll)) {
        throw "Expected the built Card Module at '$dll'."
    }

    $msi = Join-Path $OutputDirectory "ReFineID.CardDriver-$productVersion-$arch.msi"
    Write-Host "Packaging $msi"
    & wix build `
        (Join-Path $PSScriptRoot 'ReFineID.CardDriver.wxs') `
        -arch $arch `
        -define "ProductVersion=$productVersion" `
        -define "MinidriverPath=$dll" `
        -out $msi
    if ($LASTEXITCODE -ne 0) {
        throw "wix build failed for $arch."
    }
}

Write-Host ''
Write-Host "Unsigned packages are in $OutputDirectory"

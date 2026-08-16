# Adds "Send with SecureShare" to the Windows right-click menu for any file.
# Registry path is per-user (HKCU), so no admin rights are needed.
#
# Usage (from an elevated or normal prompt):
#   powershell -ExecutionPolicy Bypass -File scripts\install_windows_share.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\install_windows_share.ps1 -ExePath "C:\Apps\SecureShare.exe"
param(
    [string]$ExePath = ""
)
$ErrorActionPreference = "Stop"

if (-not $ExePath) {
    $candidates = @(
        (Join-Path $PSScriptRoot "..\dist\SecureShare.exe"),
        (Join-Path $PSScriptRoot "..\dist\SecureShare\SecureShare.exe")
    )
    $ExePath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $ExePath -or -not (Test-Path $ExePath)) {
    Write-Error "SecureShare.exe not found. Pass -ExePath <full path to SecureShare.exe>"
    exit 1
}
$ExePath = (Resolve-Path $ExePath).Path

$verb = "HKCU:\Software\Classes\*\shell\SecureShare"
New-Item -Path $verb -Force | Out-Null
Set-ItemProperty -Path $verb -Name "(Default)" -Value "Send with SecureShare" -Force
Set-ItemProperty -Path $verb -Name "Icon" -Value ('"' + $ExePath + '"') -Force
New-Item -Path "$verb\command" -Force | Out-Null
Set-ItemProperty -Path "$verb\command" -Name "(Default)" -Value ('"' + $ExePath + '" "%1"') -Force

# Tell Explorer to reload its context-menu registrations.
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SecureShareShell {
    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}
"@
[SecureShareShell]::SHChangeNotify(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host "Installed 'Send with SecureShare' -> $ExePath"
Write-Host "If the item is not visible yet: lock/unlock Windows, restart Explorer, or sign out/in."
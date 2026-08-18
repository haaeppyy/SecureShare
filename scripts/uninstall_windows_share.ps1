# Removes "Send with SecureShare" from the Windows right-click menu.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\uninstall_windows_share.ps1
$ErrorActionPreference = "Stop"

$verb = "HKCU:\Software\Classes\*\shell\SecureShare"
Remove-Item -Path $verb -Recurse -Force -ErrorAction SilentlyContinue

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SecureShareShell {
    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}
"@
[SecureShareShell]::SHChangeNotify(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host "Removed 'Send with SecureShare' from the right-click menu."
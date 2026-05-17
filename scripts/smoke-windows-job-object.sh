#!/usr/bin/env bash
set -euo pipefail

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) ;;
  *)
    echo "SKIP: Windows Job Object smoke must run on Windows"
    exit 77
    ;;
esac

if [ "${AGENTBOX_WINDOWS_JOB_OBJECT:-0}" != "1" ]; then
  echo "SKIP: set AGENTBOX_WINDOWS_JOB_OBJECT=1 to run Windows Job Object smoke"
  exit 77
fi

if command -v pwsh >/dev/null 2>&1; then
  PS=pwsh
elif command -v powershell.exe >/dev/null 2>&1; then
  PS=powershell.exe
else
  echo "SKIP: PowerShell is required for the Windows Job Object smoke"
  exit 77
fi

"$PS" -NoProfile -ExecutionPolicy Bypass -Command '
$source = @"
using System;
using System.Runtime.InteropServices;

public static class AgentboxJobObjectSmoke {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
Add-Type -TypeDefinition $source
$name = "AgentboxSmoke-" + $PID
$handle = [AgentboxJobObjectSmoke]::CreateJobObjectW([IntPtr]::Zero, $name)
if ($handle -eq [IntPtr]::Zero) {
    throw "CreateJobObjectW failed"
}
if (-not [AgentboxJobObjectSmoke]::CloseHandle($handle)) {
    throw "CloseHandle failed"
}
Write-Output "Windows Job Object create/close smoke passed for $name"
'

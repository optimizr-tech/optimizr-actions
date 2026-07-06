# Safe git commit from PowerShell — always uses UTF-8 file (no -m mojibake).
# Usage:
#   scripts/win/git-commit-safe.ps1 -MessageFile .commit-msg.txt
#   scripts/win/git-commit-safe.ps1 -Message ":bug: fix(api): prevent stale read"

param(
    [string]$Message = '',
    [string]$MessageFile = ''
)

$ErrorActionPreference = 'Stop'
$utf8 = [System.Text.UTF8Encoding]::new($false)

if ($MessageFile) {
    if (-not (Test-Path -LiteralPath $MessageFile)) {
        throw "Message file not found: $MessageFile"
    }
    git commit -F $MessageFile
    exit $LASTEXITCODE
}

if (-not $Message) {
    throw 'Provide -Message or -MessageFile'
}

$tmp = Join-Path $env:TEMP "git-commit-msg-$(Get-Random).txt"
try {
    [System.IO.File]::WriteAllText($tmp, $Message, $utf8)
    git commit -F $tmp
    exit $LASTEXITCODE
} finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

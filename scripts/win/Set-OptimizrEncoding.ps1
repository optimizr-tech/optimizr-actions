# Canonical UTF-8 bootstrap for Optimizr org (PowerShell 5.1 + 7+).
# Dot-source from $PROFILE or Cursor terminal args.
# Reload: . C:\dev\optimizr-infra-ops\scripts\win\Set-OptimizrEncoding.ps1

function global:Set-OptimizrEncoding {
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $script:OutputEncoding = $utf8

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # PS 7+: UTF-8 console is safe and fixes gh/git display.
        [Console]::OutputEncoding = $utf8
        [Console]::InputEncoding = $utf8
        $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
    } elseif ($env:WT_SESSION -or $env:TERM_PROGRAM -eq 'vscode' -or $env:CURSOR_TRACE_ID) {
        # PS 5.1: only sync console in modern hosts.
        [Console]::OutputEncoding = $utf8
        [Console]::InputEncoding = $utf8
    }

    $env:PYTHONIOENCODING = 'utf-8'
    $env:PYTHONUTF8 = '1'

    if ($env:GH_FORCE_TTY) {
        Remove-Item Env:GH_FORCE_TTY -ErrorAction SilentlyContinue
    }
}

Set-OptimizrEncoding

# Safe gh PR/issue operations from PowerShell — avoids mojibake in --title/--body args.
# Usage:
#   pwsh scripts/win/gh-safe.ps1 -Create -TitleFile .pr-title.txt -BodyFile .pr-body.md
#   pwsh scripts/win/gh-safe.ps1 -Pr 46 -TitleFile .pr-title.txt -BodyFile .pr-body.md
#   scripts/win/gh-safe.ps1 -Issue 43 -CommentFile .comment.md

param(
    [switch]$Create,
    [int]$Pr = 0,
    [int]$Issue = 0,
    [string]$Title = '',
    [string]$TitleFile = '',
    [string]$BodyFile = '',
    [string]$CommentFile = '',
    [string]$Base = 'main',
    [string]$Head = '',
    [switch]$Draft,
    [string]$Repo = ''
)

$ErrorActionPreference = 'Stop'
$utf8 = [System.Text.UTF8Encoding]::new($false)

function Read-Utf8File([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return [System.IO.File]::ReadAllText($Path, $utf8).TrimEnd()
}

function Resolve-InfraOpsRoot {
    if ($env:OPTIMIZR_INFRA_OPS -and (Test-Path -LiteralPath "$env:OPTIMIZR_INFRA_OPS/scripts/git-hooks/validate-subject.sh")) {
        return (Resolve-Path -LiteralPath $env:OPTIMIZR_INFRA_OPS).Path
    }
    $fromScript = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
    if (Test-Path -LiteralPath "$fromScript/scripts/git-hooks/validate-subject.sh") {
        return $fromScript
    }
    throw 'Cannot find optimizr-infra-ops (set OPTIMIZR_INFRA_OPS or run from infra-ops checkout)'
}

function Invoke-BashValidator([string]$ScriptPath, [string[]]$Args) {
    if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
        throw "bash not found — install Git Bash to validate PR title/body locally"
    }
    & bash $ScriptPath @Args
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if (-not $Repo) {
    $remote = git remote get-url origin 2>$null
    if ($remote -match 'github\.com[:/](.+?)(?:\.git)?$') {
        $Repo = $Matches[1]
    }
}

if ($Create) {
    $infraOps = Resolve-InfraOpsRoot
    $title = if ($TitleFile) { Read-Utf8File $TitleFile } else { $Title }
    $bodyPath = $BodyFile

    if (-not $title) { throw 'Provide -Title or -TitleFile for -Create' }
    if (-not $bodyPath -or -not (Test-Path -LiteralPath $bodyPath)) {
        throw 'Provide -BodyFile (UTF-8 markdown) for -Create — never gh pr create --body inline'
    }

    $env:VALIDATE_SUBJECT_LABEL = 'PR title'
    Invoke-BashValidator (Join-Path $infraOps 'scripts/git-hooks/validate-subject.sh') @($title)

    $env:VALIDATE_PR_BODY_LABEL = 'PR body'
    Invoke-BashValidator (Join-Path $infraOps 'scripts/git-hooks/validate-pr-body.sh') @($bodyPath)

    $ghArgs = @('pr', 'create', '--title', $title, '--body-file', $bodyPath, '--base', $Base)
    if ($Head) { $ghArgs += @('--head', $Head) }
    if ($Draft) { $ghArgs += '--draft' }
    if ($Repo) { $ghArgs += @('--repo', $Repo) }

    & gh @ghArgs
    exit $LASTEXITCODE
}

if ($Pr -gt 0) {
    $payload = @{}
    $title = Read-Utf8File $TitleFile
    $body = Read-Utf8File $BodyFile
    if ($title) { $payload.title = $title }
    if ($body) { $payload.body = $body }
    if ($payload.Count -eq 0) {
        throw 'Provide -TitleFile and/or -BodyFile for -Pr'
    }

    $jsonPath = Join-Path $env:TEMP "gh-pr-$Pr-$(Get-Random).json"
    [System.IO.File]::WriteAllText($jsonPath, ($payload | ConvertTo-Json -Compress), $utf8)

    if (-not $Repo) {
        $Repo = (gh repo view --json nameWithOwner -q .nameWithOwner).Trim()
    }
    gh api --method PATCH "repos/$Repo/pulls/$Pr" --input $jsonPath
    Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue
    exit $LASTEXITCODE
}

if ($Issue -gt 0) {
    $body = Read-Utf8File $CommentFile
    if (-not $body) { throw 'Provide -CommentFile for -Issue' }
    $jsonPath = Join-Path $env:TEMP "gh-issue-$Issue-$(Get-Random).json"
    [System.IO.File]::WriteAllText($jsonPath, (@{ body = $body } | ConvertTo-Json -Compress), $utf8)
    if ($Repo) {
        gh api --method POST "repos/$Repo/issues/$Issue/comments" --input $jsonPath
    } else {
        gh issue comment $Issue --body-file $CommentFile
    }
    Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue
    exit $LASTEXITCODE
}

throw 'Use -Create, -Pr, or -Issue'

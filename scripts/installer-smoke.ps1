# installer-smoke.ps1 — install AgentGuard on Windows the way a user does,
# then check what the installer left behind. Run by
# .github/workflows/installer-smoke.yml under Windows PowerShell 5.1 and 7.
#
#   -Mode published  the public one-liner: irm .../releases/latest/download/install.ps1 | iex
#   -Mode local      this checkout's scripts/install.ps1, installing -Want
#   -Engine          which PowerShell runs the installer: powershell (5.1) or pwsh
#
# The installer adds its folder to the user PATH. With AGENTGUARD_NO_MODIFY_PATH=1
# already set, the check flips to "PATH left alone" — for runs on a real machine.
param(
    [ValidateSet('published', 'local')] [string] $Mode = 'published',
    [Parameter(Mandatory = $true)] [string] $Want,
    [ValidateSet('powershell', 'pwsh')] [string] $Engine = 'powershell'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = 'Caua-ferraz/AgentGuard'
$Url = "https://github.com/$Repo/releases/latest/download/install.ps1"
$Want = $Want -replace '^v', ''
$WantRe = [regex]::Escape($Want)
$env:AGENTGUARD_NO_UPDATE_CHECK = '1'

function Pass([string] $Message) { Write-Host "PASS  $Message" }
function Fail([string] $Message) { Write-Host "FAIL  $Message"; exit 1 }

# Runs the installer under test in a fresh $Engine process, as a user would:
# the one-liner, or this checkout's script through the same `iex` path.
function Install-AgentGuard {
    $ErrorActionPreference = 'Continue'  # a failing install writes to stderr
    if ($Mode -eq 'published') {
        $cmd = "irm $Url | iex"
    } else {
        $env:AGENTGUARD_VERSION = $Want
        $cmd = "iex (Get-Content -Raw '$PSScriptRoot\install.ps1')"
    }
    $out = & $Engine -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1 | Out-String
    $code = $LASTEXITCODE
    Remove-Item Env:AGENTGUARD_VERSION -ErrorAction SilentlyContinue
    return @{ Out = $out; Code = $code }
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
Write-Host "== $Mode installer via $Engine, windows/$arch, expecting $Want"

# 1. Fresh install.
$r = Install-AgentGuard
$r.Out.Trim() -split "`n" | ForEach-Object { Write-Host "    | $($_.TrimEnd())" }
if ($r.Code -ne 0) { Fail "installer exited $($r.Code)" }
if ($r.Out -match 'Checksum verified') { Pass 'checksum verified' } else { Fail "no 'Checksum verified' line" }
if ($r.Out -match "Installed AgentGuard $WantRe") { Pass "installed $Want" } else { Fail "no 'Installed AgentGuard $Want'" }

# 2. All three binaries, runnable, at the expected version.
$dir = if ($env:AGENTGUARD_INSTALL_DIR) { $env:AGENTGUARD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\AgentGuard\bin' }
foreach ($t in 'agentguard', 'agentguard-mcp-gateway', 'agentguard-llm-proxy') {
    if (Test-Path (Join-Path $dir "$t.exe")) { Pass "$t.exe installed" } else { Fail "missing $dir\$t.exe" }
}
$v = (& (Join-Path $dir 'agentguard.exe') --version 2>&1 | Out-String).Trim()
if ($v -match $WantRe) { Pass "agentguard --version -> $v" } else { Fail "version was: $v" }

# 3. PATH: added by default, left alone when the operator opted out.
$onPath = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $dir
if ($env:AGENTGUARD_NO_MODIFY_PATH -eq '1') {
    if (-not $onPath) { Pass 'AGENTGUARD_NO_MODIFY_PATH=1 left the user PATH alone' } else { Fail 'user PATH changed despite AGENTGUARD_NO_MODIFY_PATH=1' }
} else {
    if ($onPath) { Pass 'install folder added to the user PATH' } else { Fail 'install folder not on the user PATH' }
}

# 4. The starter policy exists and validates.
$policy = Join-Path $env:APPDATA 'agentguard\default.yaml'
if (Test-Path $policy) { Pass "starter policy at $policy" } else { Fail 'no starter policy' }
& (Join-Path $dir 'agentguard.exe') validate --policy $policy *> $null
if ($LASTEXITCODE -eq 0) { Pass 'starter policy validates' } else { Fail 'starter policy failed validate' }

# 5. Running it again reinstalls cleanly and keeps the operator's policy.
Add-Content -Path $policy -Value '# operator edit'
$r2 = Install-AgentGuard
if ($r2.Code -eq 0 -and $r2.Out -match "Installed AgentGuard $WantRe") { Pass "rerun reinstalls $Want" } else { Write-Host $r2.Out; Fail 'unexpected rerun output' }
if ((Get-Content $policy -Tail 1) -eq '# operator edit') { Pass 'rerun kept the existing policy' } else { Fail 'rerun overwrote the policy' }

# 6. A tampered archive is refused and nothing is installed. The mirror is
#    served over HTTP: PowerShell 7's Invoke-WebRequest rejects file:// URLs.
$tmp = [IO.Path]::GetTempPath()
$mirror = Join-Path $tmp ('ag-mirror-' + [Guid]::NewGuid().ToString('N'))
$target = Join-Path $tmp ('ag-target-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $mirror | Out-Null
$archive = "agentguard_${Want}_windows_$arch.zip"
$base = "https://github.com/$Repo/releases/download/v$Want"
Invoke-WebRequest -UseBasicParsing "$base/$archive" -OutFile (Join-Path $mirror $archive)
Invoke-WebRequest -UseBasicParsing "$base/checksums.txt" -OutFile (Join-Path $mirror 'checksums.txt')
[IO.File]::AppendAllText((Join-Path $mirror $archive), 'tampered')

$port = Get-Random -Minimum 20000 -Maximum 40000
$server = Start-Process -FilePath python -ArgumentList '-m', 'http.server', $port, '--bind', '127.0.0.1', '--directory', $mirror -PassThru -WindowStyle Hidden
try {
    for ($i = 0; $i -lt 50; $i++) {
        try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$port/checksums.txt" | Out-Null; break } catch { Start-Sleep -Milliseconds 200 }
    }
    $saved = @{ Url = $env:AGENTGUARD_DOWNLOAD_URL; Dir = $env:AGENTGUARD_INSTALL_DIR; Path = $env:AGENTGUARD_NO_MODIFY_PATH }
    $env:AGENTGUARD_DOWNLOAD_URL = "http://127.0.0.1:$port"
    $env:AGENTGUARD_INSTALL_DIR = $target
    $env:AGENTGUARD_NO_MODIFY_PATH = '1'
    $t = Install-AgentGuard
    $env:AGENTGUARD_DOWNLOAD_URL = $saved.Url; $env:AGENTGUARD_INSTALL_DIR = $saved.Dir; $env:AGENTGUARD_NO_MODIFY_PATH = $saved.Path
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
if ($t.Code -ne 0 -and $t.Out -match 'checksum mismatch') { Pass 'tampered archive refused (checksum mismatch)' } else { Write-Host $t.Out; Fail 'tampered archive was not refused for its checksum' }
if (-not (Test-Path (Join-Path $target 'agentguard.exe'))) { Pass 'nothing installed from the tampered archive' } else { Fail 'a binary was installed' }

Write-Host 'ALL PASS'

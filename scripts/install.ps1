# install.ps1 - Install, update or uninstall AgentGuard (Windows).
#
#   irm https://github.com/Caua-ferraz/AgentGuard/releases/latest/download/install.ps1 | iex
#   $env:AGENTGUARD_UNINSTALL=1; irm https://github.com/Caua-ferraz/AgentGuard/releases/latest/download/install.ps1 | iex
#
# Running it again updates to the latest release. It downloads the archive for
# this CPU from GitHub Releases, verifies it against the release's
# checksums.txt, installs agentguard.exe, agentguard-mcp-gateway.exe and
# agentguard-llm-proxy.exe, and adds the install folder to the user PATH.
#
# Environment variables:
#   AGENTGUARD_VERSION         version to install, e.g. 1.2.0 (default: this
#                              script's release, or the latest release)
#   AGENTGUARD_INSTALL_DIR     where the binaries go
#                              (default: %LOCALAPPDATA%\Programs\AgentGuard\bin)
#   AGENTGUARD_DOWNLOAD_URL    base URL holding the release assets, for mirrors
#                              and air-gapped installs (default: GitHub Releases)
#   AGENTGUARD_NO_MODIFY_PATH  set to 1 to leave the user PATH unchanged
#   AGENTGUARD_UNINSTALL       set to 1 to remove the binaries and the PATH
#                              entry instead; the policy folder is kept
#   AGENTGUARD_PURGE           with AGENTGUARD_UNINSTALL: delete the policy
#                              folder too
# AGENTGUARD_UNINSTALL and AGENTGUARD_PURGE are cleared as soon as they are
# read, so a later install in the same window installs.
#
# Works in Windows PowerShell 5.1 and PowerShell 7. Everything runs inside one
# script block so that, piped into `iex`, it neither leaks variables into the
# caller's session nor closes it on error (it throws instead of calling exit).

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # the progress bar makes downloads far slower in 5.1

    $Repo = 'Caua-ferraz/AgentGuard'
    $Tools = @('agentguard', 'agentguard-mcp-gateway', 'agentguard-llm-proxy')
    # The release workflow replaces this placeholder with the release's version,
    # so a script downloaded from a given release installs that release. Run
    # from a source checkout, the placeholder survives and the latest release
    # is used.
    $ReleaseVersion = '@AGENTGUARD_VERSION@'

    function Test-Enabled([string] $Value) { $Value -and $Value -notin @('0', 'false', 'no') }

    # "1.3.0-rc1" -> 1.3.0; $null when there is no leading number.
    function ConvertTo-Release([string] $Value) {
        $m = [regex]::Match("$Value", '^(\d+)(?:\.(\d+))?(?:\.(\d+))?')
        if (-not $m.Success) { return $null }
        [version]::new([int]$m.Groups[1].Value, [int]('0' + $m.Groups[2].Value), [int]('0' + $m.Groups[3].Value))
    }

    $uninstall = Test-Enabled $env:AGENTGUARD_UNINSTALL
    $purge = Test-Enabled $env:AGENTGUARD_PURGE
    Remove-Item Env:\AGENTGUARD_UNINSTALL, Env:\AGENTGUARD_PURGE -ErrorAction SilentlyContinue
    if ($purge -and -not $uninstall) {
        throw 'agentguard install: AGENTGUARD_PURGE only applies together with AGENTGUARD_UNINSTALL'
    }

    # Where the binaries and the starter policy go. Install and uninstall must
    # agree on both, so they are worked out once.
    $dir = if ($env:AGENTGUARD_INSTALL_DIR) { $env:AGENTGUARD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\AgentGuard\bin' }
    $confdir = Join-Path $env:APPDATA 'agentguard'

    if ($uninstall) {
        $present = @($Tools | Where-Object { Test-Path (Join-Path $dir "$_.exe") })
        if ($present.Count -eq 0) {
            Write-Host "AgentGuard is not installed in $dir; nothing to remove."
            return
        }

        # A running .exe cannot be deleted. Check all three first, so an
        # uninstall never stops halfway.
        $running = @(Get-Process -Name $Tools -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -and $_.Path.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase) })
        if ($running.Count -gt 0) {
            $list = ($running | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ', '
            throw "agentguard install: AgentGuard is running: $list. Stop it, then run the uninstall again."
        }

        foreach ($tool in $Tools) {
            $exe = Join-Path $dir "$tool.exe"
            Remove-Item $exe, "$exe.old" -Force -ErrorAction SilentlyContinue
            if (Test-Path $exe) { throw "agentguard install: could not remove $exe" }
        }
        Write-Host "Removed agentguard.exe, agentguard-mcp-gateway.exe and agentguard-llm-proxy.exe from $dir"

        # The default folders are the installer's own; leave a custom one alone.
        if (-not $env:AGENTGUARD_INSTALL_DIR) {
            foreach ($folder in @($dir, (Split-Path $dir -Parent))) {
                if ((Test-Path $folder) -and -not (Get-ChildItem $folder -Force)) { Remove-Item $folder -Force }
            }
        }

        # Take out exactly the entry the installer added; every other entry,
        # empty ones included, stays as it was.
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $parts = @("$userPath" -split ';')
        if ($parts -contains $dir) {
            if ($env:AGENTGUARD_NO_MODIFY_PATH -eq '1') {
                Write-Host "$dir is still on your user PATH (AGENTGUARD_NO_MODIFY_PATH=1); remove it yourself if you added it."
            } else {
                [Environment]::SetEnvironmentVariable('Path', (($parts | Where-Object { $_ -ne $dir }) -join ';'), 'User')
                $env:Path = (@($env:Path -split ';') | Where-Object { $_ -ne $dir }) -join ';'
                Write-Host "Removed $dir from your user PATH"
            }
        }

        if ($purge) {
            if ((Split-Path $confdir -Leaf) -ne 'agentguard') { throw "agentguard install: refusing to delete unexpected folder $confdir" }
            if (Test-Path $confdir) {
                Remove-Item $confdir -Recurse -Force
                Write-Host "Deleted the policy folder $confdir"
            }
        } elseif (Test-Path $confdir) {
            Write-Host "Kept your policy folder $confdir (delete it yourself, or uninstall again with AGENTGUARD_PURGE=1)"
        }
        Write-Host 'Audit logs and the state database live where you ran `agentguard serve`; they were not touched.'
        return
    }

    # Windows PowerShell 5.1 does not offer TLS 1.2 by default; GitHub requires it.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($cpu) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "agentguard install: unsupported CPU: $cpu" }
    }

    $version = $env:AGENTGUARD_VERSION
    if (-not $version -and $ReleaseVersion -notlike '*@*') { $version = $ReleaseVersion }
    if (-not $version) {
        try {
            $latest = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'agentguard-install' }
            $version = $latest.tag_name
        } catch {
            throw "agentguard install: could not look up the latest release; set AGENTGUARD_VERSION. $($_.Exception.Message)"
        }
    }
    $version = $version -replace '^v', ''

    $base = if ($env:AGENTGUARD_DOWNLOAD_URL) { $env:AGENTGUARD_DOWNLOAD_URL.TrimEnd('/') } else { "https://github.com/$Repo/releases/download/v$version" }
    $name = "agentguard_${version}_windows_$arch"
    $archive = "$name.zip"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("agentguard-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading AgentGuard $version for windows/$arch"
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive)
        Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt')

        # checksums.txt is sha256sum output; a "*" before the name marks binary mode.
        $expected = $null
        foreach ($line in Get-Content (Join-Path $tmp 'checksums.txt')) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $archive) { $expected = $parts[0].ToLower() }
        }
        if (-not $expected) { throw "agentguard install: $archive is not listed in checksums.txt" }
        $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLower()
        if ($expected -ne $actual) { throw "agentguard install: checksum mismatch for $archive (expected $expected, got $actual)" }
        Write-Host 'Checksum verified'

        Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force

        New-Item -ItemType Directory -Path $dir -Force | Out-Null

        $previous = $null
        $current = Join-Path $dir 'agentguard.exe'
        if (Test-Path $current) {
            # The update check would add a network call and a stderr notice here.
            $env:AGENTGUARD_NO_UPDATE_CHECK = '1'
            try { $previous = ((& $current --version) -split ' ')[1] } catch { $previous = $null }
            Remove-Item Env:\AGENTGUARD_NO_UPDATE_CHECK
        }

        foreach ($tool in $Tools) {
            $target = Join-Path $dir "$tool.exe"
            # A running .exe cannot be overwritten on Windows, but it can be
            # renamed; move the old copy aside first so updates work while
            # the server is running, and clean it up when possible.
            if (Test-Path $target) {
                $old = "$target.old"
                if (Test-Path $old) { Remove-Item $old -Force -ErrorAction SilentlyContinue }
                Move-Item $target $old -Force
            }
            Copy-Item (Join-Path $tmp "$name\$tool.exe") $target -Force
            Remove-Item "$target.old" -Force -ErrorAction SilentlyContinue
        }

        $was = ConvertTo-Release $previous
        $now = ConvertTo-Release $version
        if (-not $previous) {
            Write-Host "Installed AgentGuard $version in $dir"
        } elseif ($previous -eq $version) {
            Write-Host "Reinstalled AgentGuard $version in $dir (it was already on this version)"
        } elseif ($was -and $now -and $now -lt $was) {
            Write-Host "Downgraded AgentGuard $previous -> $version in $dir"
            $how = if ($env:AGENTGUARD_VERSION) { 'Unset AGENTGUARD_VERSION to install the latest release.' } else { 'The install command from releases/latest installs the newest release.' }
            Write-Host "Warning: $version is older than the $previous you had. $how" -ForegroundColor Yellow
        } else {
            Write-Host "Updated AgentGuard $previous -> $version in $dir"
        }

        # Starter policy, so `serve` has something to load on a fresh machine.
        # An existing file is the operator's policy and is never overwritten.
        $policy = Join-Path $confdir 'default.yaml'
        if (-not (Test-Path $policy)) {
            New-Item -ItemType Directory -Path $confdir -Force | Out-Null
            Copy-Item (Join-Path $tmp "$name\configs\default.yaml") $policy
            Write-Host "Starter policy written to $policy"
        }

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $onPath = ($userPath -split ';') -contains $dir
        if (-not $onPath) {
            if ($env:AGENTGUARD_NO_MODIFY_PATH -eq '1') {
                Write-Host ''
                Write-Host "$dir is not on your PATH; add it to run agentguard from any folder."
            } else {
                $newPath = if ($userPath) { "$userPath;$dir" } else { $dir }
                [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
                $env:Path = "$env:Path;$dir"
                Write-Host "Added $dir to your user PATH (new terminals pick it up)."
            }
        }

        Write-Host ''
        Write-Host "Next: agentguard serve --policy `"$policy`" --dashboard"
        Write-Host "Docs: https://github.com/$Repo#quickstart"
        Write-Host 'To update later, run the same install command again.'
        Write-Host "To uninstall: `$env:AGENTGUARD_UNINSTALL=1; irm https://github.com/$Repo/releases/latest/download/install.ps1 | iex"
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

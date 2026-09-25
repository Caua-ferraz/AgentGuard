# install.ps1 - Install or update AgentGuard (Windows).
#
#   irm https://github.com/Caua-ferraz/AgentGuard/releases/latest/download/install.ps1 | iex
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

        $dir = if ($env:AGENTGUARD_INSTALL_DIR) { $env:AGENTGUARD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\AgentGuard\bin' }
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

        if ($previous -and $previous -ne $version) {
            Write-Host "Updated AgentGuard $previous -> $version in $dir"
        } else {
            Write-Host "Installed AgentGuard $version in $dir"
        }

        # Starter policy, so `serve` has something to load on a fresh machine.
        # An existing file is the operator's policy and is never overwritten.
        $confdir = Join-Path $env:APPDATA 'agentguard'
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
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Windows dependency installation helpers. Dot-source from run.ps1.
# Downloads are pinned in windows-tools.json and verified before use.
# Version checks never receive a target. No scans or scope edits happen here.

$WindowsSetupDir = $PSScriptRoot

function Get-WindowsSetupConfig {
    Get-Content -LiteralPath (Join-Path $WindowsSetupDir 'windows-tools.json') -Raw -Encoding UTF8 |
        ConvertFrom-Json
}

function Get-WindowsArchitecture {
    $Architecture = $env:PROCESSOR_ARCHITEW6432
    if (-not $Architecture) {
        $Architecture = $env:PROCESSOR_ARCHITECTURE
    }
    switch ($Architecture) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        'x86' { return '386' }
        default { throw "Unsupported Windows architecture: '$Architecture'. Supported: x64, ARM64, x86." }
    }
}

function Get-PythonInstallDirectory {
    param($Config)
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is missing; cannot choose a safe per-user Python installation folder.'
    }
    Join-Path (Join-Path $env:LOCALAPPDATA 'Programs\ExposureIQ') $Config.python.directory
}

function Get-PythonInstallPaths {
    param($Config)
    if ($env:LOCALAPPDATA) {
        Join-Path (Get-PythonInstallDirectory -Config $Config) 'python.exe'
        $PythonPrograms = Join-Path $env:LOCALAPPDATA 'Programs\Python'
        if (Test-Path -LiteralPath $PythonPrograms -PathType Container) {
            Get-ChildItem -LiteralPath $PythonPrograms -Directory |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName 'python.exe' }
        }
    }
}

function Get-VerifiedDownload {
    param($Asset, [string]$ProjectDir)
    $Uri = [uri]$Asset.url
    if ($Uri.Scheme -ne 'https' -or $Uri.Host -notin @('www.python.org', 'nmap.org', 'github.com') -or
        $Asset.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
        throw 'Invalid download metadata: an official HTTPS URL and SHA-256 checksum are required.'
    }
    $Filename = [IO.Path]::GetFileName($Uri.AbsolutePath)
    if ($Filename -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*\.(exe|zip)$') {
        throw 'Invalid download filename; expected an installer or ZIP archive.'
    }
    $Cache = Join-Path $ProjectDir '.tools\windows\downloads'
    $null = New-Item -ItemType Directory -Path $Cache -Force
    $Destination = Join-Path $Cache $Filename
    if (Test-Path -LiteralPath $Destination) {
        if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
            throw "Cache path is not a file: '$Destination'. Rename it and retry; it was not changed."
        }
        if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne $Asset.sha256) {
            throw "Cached download checksum mismatch. Rename '$Destination' and retry; it was not executed or overwritten."
        }
        return $Destination
    }

    $Partial = "$Destination.$([guid]::NewGuid().ToString('N')).part"
    $OriginalProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $OriginalProtocol -bor [Net.SecurityProtocolType]::Tls12
        Write-Host "==> Downloading $([IO.Path]::GetFileName($Destination))..." -ForegroundColor Cyan
        for ($Attempt = 1; $Attempt -le 2; $Attempt++) {
            try {
                Invoke-WebRequest -Uri $Uri.AbsoluteUri -OutFile $Partial -UseBasicParsing -TimeoutSec 120 `
                    -Headers @{ 'User-Agent' = 'ExposureIQ-Windows-Setup/0.1' }
                break
            } catch {
                if ($Attempt -eq 2) {
                    throw "Download failed: $Uri. Check your internet/proxy connection and retry. $($_.Exception.Message)"
                }
                Write-Warning 'Download interrupted; retrying once.'
            }
        }
        if ((Get-FileHash -LiteralPath $Partial -Algorithm SHA256).Hash -ne $Asset.sha256) {
            throw 'Download checksum mismatch; refusing to extract or run the file.'
        }
        Move-Item -LiteralPath $Partial -Destination $Destination
        return $Destination
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $OriginalProtocol
        if (Test-Path -LiteralPath $Partial -PathType Leaf) {
            Remove-Item -LiteralPath $Partial -Force
        }
    }
}

function Invoke-WindowsInstaller {
    param([string]$Executable, [string[]]$Arguments)
    # Start-Process lets the official installer request UAC consent if needed.
    # Do not elevate the whole helper, disable UAC, or bypass license screens.
    $Process = Start-Process -FilePath $Executable -ArgumentList $Arguments -Wait -PassThru
    if ($Process.ExitCode -eq 3010) {
        Write-Warning 'Windows requested a restart. This helper will not reboot your computer.'
    } elseif ($Process.ExitCode -ne 0) {
        throw "Installer failed or was cancelled (exit $($Process.ExitCode)). Run install again when ready."
    }
}

function Install-PythonRuntime {
    param($Config, [string]$ProjectDir)
    $Architecture = Get-WindowsArchitecture
    $Asset = $Config.python.architectures.$Architecture
    $Installer = Get-VerifiedDownload -Asset $Asset -ProjectDir $ProjectDir
    $Directory = Get-PythonInstallDirectory -Config $Config
    Write-Host "==> Installing Python $($Config.python.version) for this user..." -ForegroundColor Cyan
    Invoke-WindowsInstaller -Executable $Installer -Arguments @(
        '/passive', '/norestart', 'InstallAllUsers=0', 'Include_launcher=0', 'InstallLauncherAllUsers=0',
        'Include_test=0', 'Include_doc=0', 'Include_tcltk=0', 'Include_freethreaded=0',
        'AssociateFiles=0', 'Shortcuts=0', 'PrependPath=0', 'AppendPath=0',
        ('TargetDir="{0}"' -f $Directory)
    )
    if (-not (Test-Path -LiteralPath (Join-Path $Directory 'python.exe') -PathType Leaf)) {
        throw 'Python installer finished but python.exe was not found. Retry install or install Python 3.10+ manually.'
    }
}

function Get-WindowsToolInfo {
    param([ValidateSet('Nmap', 'Subfinder')][string]$Name, [string]$Executable)
    $Info = [pscustomobject]@{ Name = $Name; Path = $Executable; Ready = $false; Version = ''; Error = 'not installed' }
    if (-not $Executable -or -not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        return $Info
    }
    $Process = New-Object Diagnostics.Process
    try {
        $Process.StartInfo.FileName = $Executable
        if ($Name -eq 'Nmap') {
            $Process.StartInfo.Arguments = '--version'
            $Pattern = 'Nmap version ([0-9][\w.-]*)'
        } else {
            $Process.StartInfo.Arguments = '-version -duc -nc'
            $Pattern = '(?:Current (?:subfinder )?Version:|subfinder(?: version)?)\s*v?([0-9][\w.-]*)'
        }
        $Process.StartInfo.UseShellExecute = $false
        $Process.StartInfo.CreateNoWindow = $true
        $Process.StartInfo.RedirectStandardOutput = $true
        $Process.StartInfo.RedirectStandardError = $true
        $null = $Process.Start()
        $Stdout = $Process.StandardOutput.ReadToEndAsync()
        $Stderr = $Process.StandardError.ReadToEndAsync()
        if (-not $Process.WaitForExit(10000)) {
            $Process.Kill()
            $Info.Error = 'local version check timed out'
        } elseif (-not $Stdout.Wait(1000) -or -not $Stderr.Wait(1000)) {
            $Info.Error = 'local version output did not finish'
        } else {
            $Text = $Stdout.Result + $Stderr.Result
            if ($Process.ExitCode -eq 0 -and $Text -match $Pattern) {
                $Info.Ready = $true
                $Info.Version = $Matches[1]
                $Info.Error = ''
            } else {
                $Info.Error = "cannot verify version (exit $($Process.ExitCode)); rerun install to restore dependencies"
            }
        }
    } catch {
        $Info.Error = "cannot start: $($_.Exception.Message)"
    } finally {
        $Process.Dispose()
    }
    return $Info
}

function Find-WindowsTool {
    param([ValidateSet('Nmap', 'Subfinder')][string]$Name, $Config, [string]$ProjectDir)
    $Candidates = @()
    if ($Name -eq 'Subfinder' -and $env:SUBFINDER_PATH) {
        $Candidates += $env:SUBFINDER_PATH
    }
    $Application = Get-Command "$($Name.ToLowerInvariant()).exe" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $Application) {
        $Candidates += $Application.Source
    }
    if ($Name -eq 'Subfinder') {
        if ($env:PROCESSOR_ARCHITECTURE -or $env:PROCESSOR_ARCHITEW6432) {
            $Directory = Join-Path (Join-Path $ProjectDir '.tools\windows\subfinder') $Config.subfinder.version
            $Candidates += Join-Path (Join-Path $Directory (Get-WindowsArchitecture)) 'subfinder.exe'
        }
        $Candidates += Join-Path $HOME '.local\bin\subfinder.exe'
        $Candidates += Join-Path $HOME 'go\bin\subfinder.exe'
    } else {
        foreach ($Root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
            if ($Root) {
                $Candidates += Join-Path $Root 'Nmap\nmap.exe'
                $Candidates += Join-Path $Root 'Programs\Nmap\nmap.exe'
            }
        }
        foreach ($Key in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Nmap',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap'
        )) {
            if (Test-Path -LiteralPath $Key -ErrorAction SilentlyContinue) {
                $Installation = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
                if ($Installation.InstallLocation) {
                    $Candidates += Join-Path $Installation.InstallLocation 'nmap.exe'
                }
            }
        }
    }
    $FirstFailure = $null
    foreach ($Candidate in @($Candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            $Info = Get-WindowsToolInfo -Name $Name -Executable $Candidate
            if ($Info.Ready) {
                return $Info
            }
            if ($null -eq $FirstFailure) {
                $FirstFailure = $Info
            }
        }
    }
    if ($null -ne $FirstFailure) {
        return $FirstFailure
    }
    return Get-WindowsToolInfo -Name $Name -Executable ''
}

function Install-Subfinder {
    param($Config, [string]$ProjectDir)
    $Existing = Find-WindowsTool -Name Subfinder -Config $Config -ProjectDir $ProjectDir
    if ($Existing.Ready) {
        Write-Host "==> Reusing Subfinder $($Existing.Version): $($Existing.Path)" -ForegroundColor Cyan
        return
    }
    $Architecture = Get-WindowsArchitecture
    $ArchivePath = Get-VerifiedDownload -Asset $Config.subfinder.architectures.$Architecture -ProjectDir $ProjectDir
    $Parent = Join-Path (Join-Path $ProjectDir '.tools\windows\subfinder') $Config.subfinder.version
    $Destination = Join-Path $Parent $Architecture
    if (Test-Path -LiteralPath $Destination) {
        throw "Existing Subfinder folder is not usable. Rename '$Destination' and retry; it will not be overwritten."
    }
    $null = New-Item -ItemType Directory -Path $Parent -Force
    $Stage = Join-Path $Parent "staging-$([guid]::NewGuid().ToString('N'))"
    $null = New-Item -ItemType Directory -Path $Stage
    $Archive = $null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $Archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
        $Binary = $Archive.GetEntry('subfinder.exe')
        if ($null -eq $Binary) {
            throw 'Verified Subfinder archive has no subfinder.exe; nothing was installed.'
        }
        # Extract only named files. Never use an archive entry as a destination path.
        foreach ($Name in @('subfinder.exe', 'LICENSE', 'README.md')) {
            $Entry = $Archive.GetEntry($Name)
            if ($null -ne $Entry) {
                [IO.Compression.ZipFileExtensions]::ExtractToFile($Entry, (Join-Path $Stage $Name), $false)
            }
        }
        $Info = Get-WindowsToolInfo -Name Subfinder -Executable (Join-Path $Stage 'subfinder.exe')
        if (-not $Info.Ready) {
            throw "Downloaded Subfinder cannot run on this system: $($Info.Error)"
        }
        Move-Item -LiteralPath $Stage -Destination $Destination
        Write-Host "==> Installed Subfinder $($Info.Version): $Destination" -ForegroundColor Cyan
    } finally {
        if ($null -ne $Archive) {
            $Archive.Dispose()
        }
        if (Test-Path -LiteralPath $Stage -PathType Container) {
            # Only this invocation's freshly created staging folder is removed.
            Remove-Item -LiteralPath $Stage -Recurse -Force
        }
    }
}

function Install-Nmap {
    param($Config, [string]$ProjectDir)
    $Existing = Find-WindowsTool -Name Nmap -Config $Config -ProjectDir $ProjectDir
    if ($Existing.Ready) {
        Write-Host "==> Reusing Nmap $($Existing.Version): $($Existing.Path)" -ForegroundColor Cyan
        return
    }
    $Installer = Get-VerifiedDownload -Asset $Config.nmap -ProjectDir $ProjectDir
    Write-Host '==> Finish the official Nmap installer and accept Windows/admin prompts if authorized.' -ForegroundColor Cyan
    Write-Host 'Keep the default install folder. ExposureIQ needs Nmap, not its optional GUI or packet-capture driver.'
    # The community installer is interactive: /S is supported only by Nmap OEM.
    # Existing ExposureIQ scans use -sT -Pn, which do not require Npcap.
    Invoke-WindowsInstaller -Executable $Installer -Arguments @(
        '/NPCAP=NO', '/NCAT=NO', '/NPING=NO', '/ZENMAP=NO', '/NDIFF=NO',
        '/REGISTRYMODS=NO', '/REGISTERPATH=NO'
    )
    $Installed = Find-WindowsTool -Name Nmap -Config $Config -ProjectDir $ProjectDir
    if (-not $Installed.Ready) {
        throw "Nmap is not ready after installation: $($Installed.Error). Keep its default location and allow its required Visual C++ runtime to install, then retry."
    }
}

function Use-WindowsTools {
    param($Config, [string]$ProjectDir)
    $Directories = @()
    foreach ($Name in @('Subfinder', 'Nmap')) {
        $Info = Find-WindowsTool -Name $Name -Config $Config -ProjectDir $ProjectDir
        if ($Info.Ready) {
            $Directories += Split-Path -Parent $Info.Path
            if ($Name -eq 'Subfinder') {
                $env:SUBFINDER_PATH = $Info.Path
            }
        }
    }
    if ($Directories.Count -gt 0) {
        $env:PATH = (@($Directories | Select-Object -Unique) + @($env:PATH)) -join [IO.Path]::PathSeparator
    }
}

#requires -Version 5.1
# ExposureIQ Windows helper. 'install' sets up Python, Subfinder, and Nmap.
# No environment activation is needed. The official Nmap installer may ask
# for administrator/license confirmation; the helper itself stays unelevated.

$ErrorActionPreference = 'Stop'
$ProjectDir = $PSScriptRoot
$VenvDir = Join-Path $ProjectDir '.venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$Manifest = Join-Path $ProjectDir 'pyproject.toml'
$Command = 'start'
$Options = @()
if ($args.Count -gt 0) {
    $Command = [string]$args[0]
    if ($args.Count -gt 1) {
        $Options = @($args[1..($args.Count - 1)])
    }
}

function Show-Usage {
    Write-Host @'
ExposureIQ Windows helper (run.bat accepts the same arguments):

  .\run.ps1                         set up if needed, then open the home screen
  .\run.ps1 install                 install Python, packages, Subfinder, and Nmap
  .\run.ps1 install --python-only   Python/packages only; useful for demos
  .\run.ps1 doctor                  check dependencies locally; never scans
  .\run.ps1 demo [options]          run an example.com demo; no target traffic
  .\run.ps1 test [options]          run the offline pytest suite
  .\run.ps1 scan <domain> [options] scan passively by default
  .\run.ps1 scan <domain> --active  opt in to existing scope-gated active checks
  .\run.ps1 diff/report/scope ...   forward arguments to ExposureIQ
  .\run.ps1 --open [FILE]           browse or open saved results
  .\run.ps1 --version               show the installed version
  .\run.ps1 help                    show this help without installing anything

Only actively scan domains you own or have written permission to test.
Active checks still require authorization in scope.txt; this helper never edits it.
'@
}

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit $LASTEXITCODE): $Executable $($Arguments -join ' ')"
    }
}

function Find-Python {
    foreach ($Name in @('py.exe', 'python.exe', 'python3.exe')) {
        $Application = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -eq $Application) {
            continue
        }
        $Prefix = @()
        if ($Name -eq 'py.exe') {
            $Prefix = @('-3')
        }
        try {
            & $Application.Source @Prefix -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0) {
                return @{ Executable = $Application.Source; Prefix = $Prefix }
            }
        } catch {
            # A missing interpreter or a Windows Store alias is not usable.
        }
    }
    # The managed Python install intentionally does not change the user's PATH.
    foreach ($Candidate in @(Get-PythonInstallPaths -Config $SetupConfig)) {
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            try {
                & $Candidate -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>$null
                if ($LASTEXITCODE -eq 0) {
                    return @{ Executable = $Candidate; Prefix = @() }
                }
            } catch {
                # An incomplete existing install must not authorize later steps.
            }
        }
    }
    throw 'Python 3.10+ was not found. Run .\run.bat install to install it, or install it from https://www.python.org/downloads/windows/.'
}

function Setup-Python {
    param([switch]$ForceInstall, [switch]$InstallRuntime)
    if (-not (Test-Path -LiteralPath $VenvDir)) {
        try {
            $Launcher = Find-Python
        } catch {
            if (-not $InstallRuntime) {
                throw
            }
            Install-PythonRuntime -Config $SetupConfig -ProjectDir $ProjectDir
            $Launcher = Find-Python
        }
        Write-Host '==> Creating Python environment (.venv)...' -ForegroundColor Cyan
        Invoke-Checked -Executable $Launcher.Executable -Arguments ($Launcher.Prefix + @('-m', 'venv', $VenvDir))
    }
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        throw 'The existing .venv has no Windows Python. It may be incomplete or created on Linux/macOS. Rename it yourself, then retry; nothing was deleted.'
    }
    & $VenvPython -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    if ($LASTEXITCODE -ne 0) {
        throw 'Python in .venv must be 3.10+. Rename the old environment yourself and retry with a supported Python installation.'
    }

    $Stamp = Join-Path $VenvDir '.windows-deps.sha256'
    $ManifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash
    $InstalledHash = ''
    if (Test-Path -LiteralPath $Stamp -PathType Leaf) {
        $InstalledHash = [string](Get-Content -LiteralPath $Stamp -Raw)
    }
    if ($ForceInstall -or $InstalledHash.Trim() -ne $ManifestHash) {
        # A failed or interrupted refresh must be retried on the next run.
        Set-Content -LiteralPath $Stamp -Value '' -Encoding ascii
        Write-Host '==> Installing ExposureIQ and its Python dependencies...' -ForegroundColor Cyan
        Invoke-Checked -Executable $VenvPython -Arguments @('-m', 'pip', 'install', '--upgrade', 'pip')
        Invoke-Checked -Executable $VenvPython -Arguments @('-m', 'pip', 'install', '-e', "${ProjectDir}[dev]")
        Set-Content -LiteralPath $Stamp -Value $ManifestHash -Encoding ascii
    }
}

function Show-Doctor {
    $Ready = $true
    Write-Host '==> Local dependency check (no downloads or target requests)' -ForegroundColor Cyan
    try {
        if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
            # A working project environment does not need a launcher on PATH.
            Invoke-Checked -Executable $VenvPython -Arguments @(
                '-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
            )
            $Interpreter = $VenvPython
        } else {
            $Launcher = Find-Python
            $Interpreter = $Launcher.Executable
        }
        Write-Host "[OK] Python 3.10+: $Interpreter"
    } catch {
        Write-Host '[MISSING] Python 3.10+. Run .\run.bat install.'
        $Ready = $false
    }
    if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
        try {
            # Single quotes inside Python code survive PowerShell 5.1's native argument handling.
            $Probe = "import importlib.util, sys; names = ('requests', 'dns', 'rich', 'cryptography', 'textual', 'docx'); missing = [n for n in names if importlib.util.find_spec(n) is None]; print('Missing Python packages: ' + ', '.join(missing) if missing else 'Project Python packages found'); sys.exit(0 if not missing and sys.version_info >= (3, 10) else 1)"
            $Packages = & $VenvPython -c $Probe 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] $Packages ($VenvPython)"
            } else {
                Write-Host "[MISSING] Project environment: $Packages. Run .\run.bat install."
                $Ready = $false
            }
        } catch {
            Write-Host "[MISSING] Project environment cannot start: $($_.Exception.Message)"
            $Ready = $false
        }
    } else {
        Write-Host '[MISSING] Project .venv. Run .\run.bat install.'
        $Ready = $false
    }
    foreach ($Name in @('Subfinder', 'Nmap')) {
        $Info = Find-WindowsTool -Name $Name -Config $SetupConfig -ProjectDir $ProjectDir
        if ($Info.Ready) {
            Write-Host "[OK] $Name $($Info.Version): $($Info.Path)"
        } else {
            Write-Host "[MISSING] ${Name}: $($Info.Error). Run .\run.bat install."
            $Ready = $false
        }
    }
    Write-Host 'This checks local setup only. Web connection errors and crt.sh outages can still occur.'
    if ($Ready) { return 0 }
    return 1
}

if ($Command -in @('help', '-h', '--help')) {
    Show-Usage
    exit 0
}
if ($Command -notin @('start', 'install', 'doctor', 'demo', 'test', 'scan', 'diff', 'report', 'scope', '--open', '--op', '--version')) {
    Show-Usage
    [Console]::Error.WriteLine("ERROR: Unknown command: $Command")
    exit 2
}
$PythonOnly = $Command -eq 'install' -and $Options.Count -eq 1 -and $Options[0] -eq '--python-only'
if (($Command -in @('start', 'doctor') -and $Options.Count -gt 0) -or
    ($Command -eq 'install' -and $Options.Count -gt 0 -and -not $PythonOnly)) {
    [Console]::Error.WriteLine("ERROR: '$Command' does not accept extra arguments. Use help for available commands.")
    exit 2
}

$CliArguments = @($Command) + $Options
$Active = $false
if ($Command -eq 'start') {
    $CliArguments = @()
} elseif ($Command -eq 'demo') {
    $CliArguments = @('scan', 'example.com', '--demo') + $Options
} elseif ($Command -eq 'scan') {
    if ($Options.Count -eq 0 -or ([string]$Options[0]).StartsWith('-')) {
        [Console]::Error.WriteLine('ERROR: Usage: .\run.bat scan <domain> [options]')
        exit 2
    }
    $Active = $Options -contains '--active'
    if ($Active -and $Options -contains '--passive') {
        [Console]::Error.WriteLine('ERROR: Choose either --active or --passive, not both.')
        exit 2
    }
    $CliArguments = @('scan') + @($Options | Where-Object { $_ -ne '--active' })
    if (-not $Active -and $Options -notcontains '--passive') {
        $CliArguments += '--passive'
    }
}

$ExitCode = 0
$LocationPushed = $false
$OriginalPath = $env:PATH
$OriginalSubfinder = $env:SUBFINDER_PATH
$OriginalAutoInstall = $env:PYTHON_MANAGER_AUTOMATIC_INSTALL
try {
    # New Python launchers otherwise download a runtime when none is installed.
    # Only explicit 'install' may bootstrap Python, using our verified installer.
    $env:PYTHON_MANAGER_AUTOMATIC_INSTALL = 'false'
    Push-Location -LiteralPath $ProjectDir
    $LocationPushed = $true
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $ProjectDir 'exposureiq') -PathType Container)) {
        throw 'Keep run.ps1 and run.bat in the cloned project root, next to pyproject.toml and exposureiq/.'
    }
    . (Join-Path $ProjectDir 'scripts\windows-install.ps1')
    $SetupConfig = Get-WindowsSetupConfig
    if ($Command -eq 'doctor') {
        $ExitCode = Show-Doctor
    } else {
        Setup-Python -ForceInstall:($Command -eq 'install') -InstallRuntime:($Command -eq 'install')
        if ($Command -eq 'install' -and -not $PythonOnly) {
            Install-Subfinder -Config $SetupConfig -ProjectDir $ProjectDir
            Install-Nmap -Config $SetupConfig -ProjectDir $ProjectDir
        }
        Use-WindowsTools -Config $SetupConfig -ProjectDir $ProjectDir
        if ($Command -eq 'install') {
            if (-not $PythonOnly -and (Show-Doctor) -ne 0) {
                throw 'Setup is incomplete. Resolve the missing components shown above, then retry install.'
            }
            Write-Host '==> Ready. Try .\run.bat demo or .\run.bat to open the app.' -ForegroundColor Cyan
        } elseif ($Command -eq 'test') {
            & $VenvPython -m pytest -q @Options
            $ExitCode = $LASTEXITCODE
        } else {
            if ($Active) {
                Write-Host '==> Active checks requested. Only existing scope-authorized targets may be probed.' -ForegroundColor Cyan
            }
            & $VenvPython -m exposureiq.cli @CliArguments
            $ExitCode = $LASTEXITCODE
        }
    }
} catch {
    [Console]::Error.WriteLine("ERROR: $($_.Exception.Message)")
    $ExitCode = 1
} finally {
    $env:PATH = $OriginalPath
    $env:SUBFINDER_PATH = $OriginalSubfinder
    $env:PYTHON_MANAGER_AUTOMATIC_INSTALL = $OriginalAutoInstall
    if ($LocationPushed) {
        Pop-Location
    }
}
exit $ExitCode

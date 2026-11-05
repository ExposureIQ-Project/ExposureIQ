"""Saved download/installer fakes exercise setup without internet or real tools."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
from urllib.parse import urlparse
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Installer tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def setup(tmp_path):
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is not installed")
    project = tmp_path / "Checkout with spaces"
    project.mkdir()
    installer = tmp_path / "saved-installer.exe"
    installer.write_bytes(b"Saved installer fake, never executed")
    archive = tmp_path / "saved-subfinder.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("subfinder.exe", b"Saved Subfinder fake, never executed")
        bundle.writestr("LICENSE", "Saved license")
        bundle.writestr("../do-not-extract.txt", "Untrusted entry name")
    config = json.loads((ROOT / "scripts" / "windows-tools.json").read_text(encoding="utf-8"))
    for asset in config["python"]["architectures"].values():
        asset["sha256"] = hashlib.sha256(installer.read_bytes()).hexdigest()
    for asset in config["subfinder"]["architectures"].values():
        asset["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    config["nmap"]["sha256"] = hashlib.sha256(installer.read_bytes()).hexdigest()
    manifest = tmp_path / "saved-config.json"
    manifest.write_text(json.dumps(config), encoding="utf-8")
    harness = tmp_path / "installer-harness.ps1"
    harness.write_text(r'''
$ErrorActionPreference = 'Stop'
. $env:TEST_MODULE
$Config = Get-Content -LiteralPath $env:TEST_CONFIG -Raw | ConvertFrom-Json
$ProjectDir = $env:TEST_PROJECT
$OriginalGetInfo = (Get-Item Function:Get-WindowsToolInfo).ScriptBlock
function Record-Call {
    param($Kind, $Arguments)
    $Line = @{ kind = $Kind; args = @($Arguments) } | ConvertTo-Json -Compress
    [IO.File]::AppendAllText($env:TEST_CALLS, $Line + [Environment]::NewLine)
}
function Get-Command { param($Name, $CommandType, $ErrorAction) }
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec, $Headers)
    Record-Call -Kind download -Arguments @([string]$Uri, $TimeoutSec, $Headers['User-Agent'])
    if ($env:FAKE_HTTP_FAIL -eq '1') { throw 'Saved 502 response' }
    $Source = $env:TEST_INSTALLER
    if ([string]$Uri -like '*subfinder_*') { $Source = $env:TEST_ARCHIVE }
    Copy-Item -LiteralPath $Source -Destination $OutFile -Force
}
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru)
    Record-Call -Kind installer -Arguments (@($FilePath) + @($ArgumentList))
    $Code = 0
    if ($env:FAKE_INSTALL_EXIT) { $Code = [int]$env:FAKE_INSTALL_EXIT }
    if ($Code -eq 0 -or $Code -eq 3010) {
        if ((Split-Path -Leaf $FilePath) -like 'python-*' -and $env:FAKE_INCOMPLETE -ne '1') {
            $Directory = Get-PythonInstallDirectory -Config $Config
            $null = New-Item -ItemType Directory -Path $Directory -Force
            [IO.File]::WriteAllText((Join-Path $Directory 'python.exe'), 'Saved fake Python')
        } elseif ((Split-Path -Leaf $FilePath) -like 'nmap-*' -and $env:FAKE_INCOMPLETE -ne '1') {
            $Directory = Join-Path $env:ProgramFiles 'Nmap'
            $null = New-Item -ItemType Directory -Path $Directory -Force
            [IO.File]::WriteAllText((Join-Path $Directory 'nmap.exe'), 'Saved fake Nmap')
        }
    }
    return [pscustomobject]@{ ExitCode = $Code }
}
function Get-WindowsToolInfo {
    param($Name, $Executable)
    $Ready = $Executable -and $Executable.StartsWith($env:TEST_PROJECT) -and
        (Test-Path -LiteralPath $Executable -PathType Leaf) -and $env:FAKE_BROKEN -ne '1'
    return [pscustomobject]@{ Name = $Name; Path = $Executable; Ready = [bool]$Ready; Version = 'test'; Error = 'saved version-check failure' }
}
try {
    $Result = & ([scriptblock]::Create($env:TEST_ACTION))
    Write-Output ('RESULT:' + (ConvertTo-Json -InputObject $Result -Depth 5 -Compress))
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
''', encoding="utf-8")

    def run(action, **overrides):
        environment = os.environ.copy()
        environment.update(
            TEST_MODULE=str(ROOT / "scripts" / "windows-install.ps1"),
            TEST_CONFIG=str(manifest), TEST_PROJECT=str(project), TEST_ACTION=action,
            TEST_INSTALLER=str(installer), TEST_ARCHIVE=str(archive),
            TEST_CALLS=str(project / "calls.jsonl"), TEST_PYTHON=sys.executable,
            PROCESSOR_ARCHITECTURE="AMD64", PROCESSOR_ARCHITEW6432="",
            LOCALAPPDATA=str(project / "Local App Data"), ProgramFiles=str(project / "Program Files"),
            SUBFINDER_PATH="", POWERSHELL_TELEMETRY_OPTOUT="1", POWERSHELL_UPDATECHECK="Off",
        )
        environment["ProgramFiles(x86)"] = str(project / "Program Files x86")
        environment.update(overrides)
        return subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
            cwd=project, env=environment, capture_output=True, text=True, timeout=45,
        )

    return project, manifest, run


def result_value(result):
    assert result.returncode == 0, result.stdout + result.stderr
    line = next(line for line in result.stdout.splitlines() if line.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


def recorded(project, kind):
    log = project / "calls.jsonl"
    if not log.exists():
        return []
    return [entry for line in log.read_text(encoding="utf-8").splitlines()
            if (entry := json.loads(line))["kind"] == kind]


def test_pinned_manifest_uses_official_publishers_and_complete_architectures():
    config = json.loads((ROOT / "scripts" / "windows-tools.json").read_text(encoding="utf-8"))
    for name, host in (("python", "www.python.org"), ("subfinder", "github.com")):
        assert set(config[name]["architectures"]) == {"amd64", "arm64", "386"}
        for asset in config[name]["architectures"].values():
            assert urlparse(asset["url"]).scheme == "https"
            assert urlparse(asset["url"]).netloc == host
            assert config[name]["version"] in asset["url"]
            assert re.fullmatch(r"[a-f0-9]{64}", asset["sha256"])
    assert urlparse(config["nmap"]["url"]).netloc == "nmap.org"
    assert re.fullmatch(r"[a-f0-9]{64}", config["nmap"]["sha256"])
    assert config["nmap"]["hash_source"].startswith("https://nmap.org/dist/sigs/")


@pytest.mark.parametrize("architecture,wow64,expected", [
    ("AMD64", "", "amd64"), ("ARM64", "", "arm64"), ("x86", "", "386"),
    ("x86", "AMD64", "amd64"), ("x86", "ARM64", "arm64"),
])
def test_architecture_selection_respects_host_not_shell_bitness(setup, architecture, wow64, expected):
    _, _, run = setup
    assert result_value(run("Get-WindowsArchitecture", PROCESSOR_ARCHITECTURE=architecture,
                            PROCESSOR_ARCHITEW6432=wow64)) == expected


def test_unknown_architecture_stops_before_download(setup):
    project, _, run = setup
    result = run("Install-PythonRuntime -Config $Config -ProjectDir $ProjectDir", PROCESSOR_ARCHITECTURE="unknown")
    assert result.returncode == 1
    assert "Unsupported Windows architecture" in result.stderr
    assert not recorded(project, "download")


def test_verified_download_is_cached_and_has_bounded_honest_requests(setup):
    project, _, run = setup
    action = "Get-VerifiedDownload -Asset $Config.nmap -ProjectDir $ProjectDir"
    path = Path(result_value(run(action)))
    assert path.is_file()
    assert result_value(run(action)) == str(path)
    assert len(recorded(project, "download")) == 1
    assert recorded(project, "download")[0]["args"][1:] == [120, "ExposureIQ-Windows-Setup/0.1"]


@pytest.mark.parametrize("mutation,error", [
    ("$Config.nmap.sha256 = '0' * 64", "checksum mismatch"),
    ("$Config.nmap.url = 'http://nmap.org/dist/test.exe'", "official HTTPS"),
    ("$Config.nmap.url = 'https://example.com/test.exe'", "official HTTPS"),
    ("$Config.nmap.sha256 = 'bad'", "SHA-256 checksum"),
    ("$Config.nmap.url = 'https://nmap.org/dist/'", "download filename"),
])
def test_invalid_downloads_are_never_installed_and_partial_files_are_removed(setup, mutation, error):
    project, _, run = setup
    result = run(mutation + "; Install-Nmap -Config $Config -ProjectDir $ProjectDir")
    assert result.returncode == 1
    assert error in result.stderr
    assert not recorded(project, "installer")
    assert not list(project.rglob("*.part"))


def test_corrupt_cached_file_is_preserved_and_not_executed(setup):
    project, _, run = setup
    path = Path(result_value(run("Get-VerifiedDownload -Asset $Config.nmap -ProjectDir $ProjectDir")))
    path.write_bytes(b"Existing user work")
    result = run("Install-Nmap -Config $Config -ProjectDir $ProjectDir")
    assert result.returncode == 1
    assert "Cached download checksum mismatch" in result.stderr
    assert path.read_bytes() == b"Existing user work"
    assert len(recorded(project, "download")) == 1
    assert not recorded(project, "installer")


def test_http_failure_retries_once_and_does_not_execute_anything(setup):
    project, _, run = setup
    result = run("Install-Nmap -Config $Config -ProjectDir $ProjectDir", FAKE_HTTP_FAIL="1")
    assert result.returncode == 1
    assert "Download failed" in result.stderr
    assert len(recorded(project, "download")) == 2
    assert not recorded(project, "installer")
    assert not list(project.rglob("*.part"))


@pytest.mark.parametrize("architecture,asset", [("AMD64", "amd64"), ("ARM64", "arm64"), ("x86", "386")])
def test_subfinder_extracts_only_named_files_and_reuses_working_tool(setup, architecture, asset):
    project, _, run = setup
    action = "Install-Subfinder -Config $Config -ProjectDir $ProjectDir"
    result_value(run(action, PROCESSOR_ARCHITECTURE=architecture))
    binary = project / ".tools" / "windows" / "subfinder" / "2.17.0" / asset / "subfinder.exe"
    assert binary.is_file()
    assert (binary.parent / "LICENSE").is_file()
    assert not list(project.rglob("do-not-extract.txt"))
    assert not list(project.rglob("staging-*"))
    result_value(run(action, PROCESSOR_ARCHITECTURE=architecture))
    assert len(recorded(project, "download")) == 1
    assert not recorded(project, "installer")  # No Go compiler or executable installer needed.


def test_subfinder_version_failure_cleans_staging_without_installing(setup):
    project, _, run = setup
    result = run("Install-Subfinder -Config $Config -ProjectDir $ProjectDir", FAKE_BROKEN="1")
    assert result.returncode == 1
    assert "Downloaded Subfinder cannot run" in result.stderr
    assert not (project / ".tools" / "windows" / "subfinder" / "2.17.0" / "amd64").exists()
    assert not list(project.rglob("staging-*"))


def test_nmap_uses_official_interactive_installer_without_extra_drivers_or_registry_tuning(setup):
    project, _, run = setup
    action = "Install-Nmap -Config $Config -ProjectDir $ProjectDir"
    result_value(run(action))
    arguments = recorded(project, "installer")[0]["args"]
    assert arguments[1:] == ["/NPCAP=NO", "/NCAT=NO", "/NPING=NO", "/ZENMAP=NO", "/NDIFF=NO",
                             "/REGISTRYMODS=NO", "/REGISTERPATH=NO"]
    assert "/S" not in arguments
    result_value(run(action))
    assert len(recorded(project, "installer")) == 1
    assert len(recorded(project, "download")) == 1


@pytest.mark.parametrize("architecture,filename", [
    ("AMD64", "python-3.14.10-amd64.exe"), ("ARM64", "python-3.14.10-arm64.exe"),
    ("x86", "python-3.14.10.exe"),
])
def test_python_install_is_per_user_with_a_quoted_target_and_no_path_change(setup, architecture, filename):
    project, _, run = setup
    result_value(run("Install-PythonRuntime -Config $Config -ProjectDir $ProjectDir",
                     PROCESSOR_ARCHITECTURE=architecture))
    arguments = recorded(project, "installer")[0]["args"]
    assert Path(arguments[0]).name == filename
    assert "/passive" in arguments
    assert "/norestart" in arguments
    assert "InstallAllUsers=0" in arguments
    assert "PrependPath=0" in arguments and "AppendPath=0" in arguments
    assert "Include_launcher=0" in arguments
    assert any(argument.startswith('TargetDir="') and "Local App Data" in argument for argument in arguments)


def test_nmap_default_x86_location_is_found_without_path_edits(setup):
    project, _, run = setup
    executable = project / "Program Files x86" / "Nmap" / "nmap.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"Saved existing tool fake")
    info = result_value(run("Find-WindowsTool -Name Nmap -Config $Config -ProjectDir $ProjectDir"))
    assert info["Ready"] is True
    assert Path(info["Path"]) == executable
    assert not recorded(project, "download")


@pytest.mark.parametrize("overrides,error", [
    ({"FAKE_INSTALL_EXIT": "1223"}, "Installer failed or was cancelled"),
    ({"FAKE_INCOMPLETE": "1"}, "Nmap is not ready after installation"),
])
def test_installer_cancellation_or_incomplete_install_is_not_success(setup, overrides, error):
    _, _, run = setup
    result = run("Install-Nmap -Config $Config -ProjectDir $ProjectDir", **overrides)
    assert result.returncode == 1
    assert error in result.stderr


def test_restart_is_reported_but_not_forced(setup):
    _, _, run = setup
    result = run("Install-Nmap -Config $Config -ProjectDir $ProjectDir", FAKE_INSTALL_EXIT="3010")
    result_value(result)
    assert "will not reboot" in result.stdout


def test_wrong_program_is_not_accepted_as_nmap(setup):
    _, _, run = setup
    info = result_value(run("& $OriginalGetInfo -Name Nmap -Executable $env:TEST_PYTHON"))
    assert info["Ready"] is False  # python --version is not Nmap --version.
    assert "cannot verify version" in info["Error"]


@pytest.mark.skipif(os.name != "posix" or " " in sys.executable, reason="Executable script fake requires POSIX")
@pytest.mark.parametrize("name,output", [("Nmap", "Nmap version 7.993"), ("Subfinder", "Current Version: v2.17.0")])
def test_real_version_check_reads_stdout_and_stderr_without_a_target(setup, name, output):
    project, _, run = setup
    executable = project / "fake-tool.exe"
    executable.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"assert sys.argv[1:] == {['--version'] if name == 'Nmap' else ['-version', '-duc', '-nc']!r}\n"
        f"print({output!r}, file=sys.stderr)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    info = result_value(run(f"& $OriginalGetInfo -Name {name} -Executable $env:TEST_EXE", TEST_EXE=str(executable)))
    assert info["Ready"] is True
    assert info["Version"] == ("7.993" if name == "Nmap" else "2.17.0")

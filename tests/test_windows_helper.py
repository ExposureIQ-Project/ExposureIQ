"""Offline helper tests: fake pip, launcher, CLI, and pytest; never scan a target.

Runtime tests skip when PowerShell is unavailable. They work with Windows
PowerShell 5.1 or PowerShell 7 on Linux using a temporary Windows-shaped venv.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Helper tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture(scope="module")
def powershell():
    executable = shutil.which("pwsh") or shutil.which("powershell.exe")
    if executable is None:
        pytest.skip("PowerShell is not installed; Windows helper runtime tests skipped")
    return executable


@pytest.fixture
def helper(tmp_path, powershell):
    project = tmp_path / "Windows checkout with spaces"
    project.mkdir()
    shutil.copyfile(ROOT / "run.ps1", project / "run.ps1")
    scripts = project / "scripts"
    scripts.mkdir()
    config = json.loads((ROOT / "scripts" / "windows-tools.json").read_text(encoding="utf-8"))
    installer = tmp_path / "fake-installer.exe"
    installer.write_bytes(b"Saved fake installer; never executed")
    archive = tmp_path / "fake-subfinder.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("subfinder.exe", b"Saved fake executable; never executed")
        bundle.writestr("LICENSE", "Saved test license")
    installer_hash = hashlib.sha256(installer.read_bytes()).hexdigest()
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    for asset in config["python"]["architectures"].values():
        asset["sha256"] = installer_hash
    for asset in config["subfinder"]["architectures"].values():
        asset["sha256"] = archive_hash
    config["nmap"]["sha256"] = installer_hash
    # A real offline venv supplies the fake runtime on Windows and Linux.
    config["python"]["directory"] = "FakeRuntime/Scripts"
    (scripts / "windows-tools.json").write_text(json.dumps(config), encoding="utf-8")
    (project / "pyproject.toml").write_text('[project]\nname = "fake-exposureiq"\n', encoding="utf-8")
    package = project / "exposureiq"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for name in ("requests", "dns", "rich", "cryptography", "textual", "docx"):
        (project / f"{name}.py").write_text("# Saved dependency fake\n", encoding="utf-8")
    (project / "_fake_log.py").write_text(
        "import json, os, socket\n"
        "from pathlib import Path\n"
        "def blocked(*args, **kwargs):\n"
        "    raise AssertionError('Helper subprocesses must not use the network')\n"
        "socket.socket.connect = blocked\n"
        "socket.create_connection = blocked\n"
        "socket.getaddrinfo = blocked\n"
        "def record(kind, arguments):\n"
        "    with Path(os.environ['TEST_CALLS']).open('a', encoding='utf-8') as log:\n"
        "        log.write(json.dumps({'kind': kind, 'args': arguments, 'cwd': os.getcwd(), 'path': os.environ.get('PATH'), 'subfinder': os.environ.get('SUBFINDER_PATH'), 'auto_install': os.environ.get('PYTHON_MANAGER_AUTOMATIC_INSTALL')}) + '\\n')\n",
        encoding="utf-8",
    )
    for name, kind, variable in (
        (project / "pip.py", "pip", "FAKE_PIP_EXIT"),
        (project / "pytest.py", "pytest", "FAKE_TEST_EXIT"),
        (package / "cli.py", "cli", "FAKE_CLI_EXIT"),
    ):
        name.write_text(
            "import os, sys\n"
            "from _fake_log import record\n"
            f"record({kind!r}, sys.argv[1:])\n"
            f"sys.exit(int(os.environ.get({variable!r}, '0')))\n",
            encoding="utf-8",
        )
    launcher = project / "_fake_launcher.py"
    launcher.write_text(
        "import os, sys, venv\n"
        "from pathlib import Path\n"
        "from _fake_log import record\n"
        "arguments = sys.argv[1:]\n"
        "record('launcher', arguments)\n"
        "if arguments[:1] == ['-3']:\n"
        "    arguments = arguments[1:]\n"
        "if arguments[:1] == ['-c']:\n"
        "    assert 'sys.version_info >= (3, 10)' in arguments[1]\n"
        "    sys.exit(int(os.environ.get('FAKE_PYTHON_EXIT', '0')))\n"
        "assert arguments[:2] == ['-m', 'venv'], arguments\n"
        "destination = Path(arguments[2])\n"
        "venv.EnvBuilder(with_pip=False).create(destination)\n"
        "if os.name != 'nt':\n"
        "    scripts = destination / 'Scripts'\n"
        "    scripts.mkdir()\n"
        "    (scripts / 'python.exe').symlink_to(destination / 'bin' / 'python')\n",
        encoding="utf-8",
    )
    # Mock downloads, installers, and external tool version checks. On POSIX,
    # also simulate Windows' Scripts/ layout when managed Python creates a venv.
    # Run the actual download/hash/extraction/discovery logic.
    mocks = r'''
function Write-TestCall {
    param($Kind, $Arguments)
    $Line = @{ kind = $Kind; args = @($Arguments); cwd = (Get-Location).Path } | ConvertTo-Json -Compress
    [IO.File]::AppendAllText($env:TEST_CALLS, $Line + [Environment]::NewLine)
}
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec, $Headers)
    Write-TestCall -Kind download -Arguments @([string]$Uri)
    if ($env:FAKE_DOWNLOAD_ERROR -eq '1') { throw 'Saved network failure' }
    $Source = $env:TEST_INSTALLER
    if ([string]$Uri -like '*subfinder_*') { $Source = $env:TEST_ARCHIVE }
    Copy-Item -LiteralPath $Source -Destination $OutFile -Force
}
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru)
    Write-TestCall -Kind installer -Arguments (@($FilePath) + @($ArgumentList))
    $Code = 0
    if ($env:FAKE_INSTALL_EXIT) { $Code = [int]$env:FAKE_INSTALL_EXIT }
    if ($Code -eq 0 -or $Code -eq 3010) {
        if ((Split-Path -Leaf $FilePath) -like 'python-*') {
            $Target = @($ArgumentList | Where-Object { $_ -like 'TargetDir=*' })[0]
            $Directory = $Target.Substring(11, $Target.Length - 12)
            & $env:TEST_PYTHON $env:TEST_LAUNCHER_SCRIPT -m venv (Split-Path -Parent $Directory)
            if ($LASTEXITCODE -ne 0) { throw 'Fake Python runtime setup failed' }
        } elseif ((Split-Path -Leaf $FilePath) -like 'nmap-*' -and $env:FAKE_NMAP_INCOMPLETE -ne '1') {
            $Directory = Join-Path $env:ProgramFiles 'Nmap'
            $null = New-Item -ItemType Directory -Path $Directory -Force
            [IO.File]::WriteAllText((Join-Path $Directory 'nmap.exe'), 'Saved fake Nmap; never executed')
        }
    }
    return [pscustomobject]@{ ExitCode = $Code }
}
function Get-WindowsToolInfo {
    param($Name, $Executable)
    $Ready = $Executable -and $Executable.StartsWith($env:TEST_BASE) -and
        (Test-Path -LiteralPath $Executable -PathType Leaf) -and $env:FAKE_TOOLS_BROKEN -ne '1'
    return [pscustomobject]@{ Name = $Name; Path = $Executable; Ready = [bool]$Ready; Version = 'test-version'; Error = 'fake tool missing or broken' }
}
$RealInvokeChecked = (Get-Item Function:Invoke-Checked).ScriptBlock
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    if ($env:TEST_POSIX -eq '1' -and $Executable -ne 'Invoke-TestPython' -and
        $Arguments.Count -ge 3 -and $Arguments[0] -eq '-m' -and $Arguments[1] -eq 'venv') {
        & $RealInvokeChecked -Executable $env:TEST_PYTHON -Arguments (@($env:TEST_LAUNCHER_SCRIPT) + $Arguments)
    } else {
        & $RealInvokeChecked -Executable $Executable -Arguments $Arguments
    }
}
'''
    (scripts / "windows-install.ps1").write_text(
        (ROOT / "scripts" / "windows-install.ps1").read_text(encoding="utf-8") + mocks,
        encoding="utf-8",
    )
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "if ($env:TEST_NATIVE_ARGUMENTS) { $PSNativeCommandArgumentPassing = $env:TEST_NATIVE_ARGUMENTS }\n"
        "function global:Get-Command {\n"
        "    param($Name, $CommandType, $ErrorAction)\n"
        "    if ($Name -eq $env:TEST_LAUNCHER) {\n"
        "        return [pscustomobject]@{ Source = 'Invoke-TestPython' }\n"
        "    }\n"
        "}\n"
        "function global:Invoke-TestPython {\n"
        "    & $env:TEST_PYTHON $env:TEST_LAUNCHER_SCRIPT @args\n"
        "    $global:LASTEXITCODE = $LASTEXITCODE\n"
        "}\n"
        "& $env:TEST_RUN_SCRIPT @args\n"
        "$Code = $LASTEXITCODE\n"
        "[IO.File]::WriteAllText($env:TEST_LOCATION, (Get-Location).Path)\n"
        "$Restored = @{ path = $env:PATH; subfinder = $env:SUBFINDER_PATH; auto_install = $env:PYTHON_MANAGER_AUTOMATIC_INSTALL } | ConvertTo-Json -Compress\n"
        "[IO.File]::WriteAllText($env:TEST_RESTORED, $Restored)\n"
        "exit $Code\n",
        encoding="utf-8",
    )
    caller = tmp_path / "unrelated working directory"
    caller.mkdir()

    def run(*arguments, **overrides):
        environment = os.environ.copy()
        environment.update(
            TEST_PYTHON=sys.executable,
            TEST_LAUNCHER="py.exe",
            TEST_LAUNCHER_SCRIPT=str(launcher),
            TEST_RUN_SCRIPT=str(project / "run.ps1"),
            TEST_CALLS=str(project / "calls.jsonl"),
            TEST_LOCATION=str(caller / "restored-location.txt"),
            TEST_RESTORED=str(caller / "restored-environment.json"),
            TEST_BASE=str(tmp_path),
            TEST_INSTALLER=str(installer),
            TEST_ARCHIVE=str(archive),
            TEST_POSIX="1" if os.name != "nt" else "",
            PROCESSOR_ARCHITECTURE="AMD64",
            PROCESSOR_ARCHITEW6432="",
            LOCALAPPDATA=str(tmp_path / "Local App Data"),
            ProgramFiles=str(tmp_path / "Program Files"),
            POWERSHELL_TELEMETRY_OPTOUT="1",
            POWERSHELL_UPDATECHECK="Off",
        )
        environment["ProgramFiles(x86)"] = str(tmp_path / "Program Files x86")
        environment.update(overrides)
        return subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness), *arguments],
            cwd=caller, env=environment, capture_output=True, text=True, timeout=60,
        )

    return project, caller, run


def calls(project, kind):
    log = project / "calls.jsonl"
    if not log.exists():
        return []
    return [entry for line in log.read_text(encoding="utf-8").splitlines()
            if (entry := json.loads(line))["kind"] == kind]


@pytest.mark.parametrize("name", ["run.ps1", "run.bat", "scripts/windows-install.ps1", "scripts/windows-tools.json"])
def test_helpers_use_utf8_without_bom_and_unix_line_endings(name):
    content = (ROOT / name).read_bytes()
    content.decode("utf-8")
    assert not content.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in content


def test_batch_wrapper_anchors_script_path_and_forwards_arguments():
    content = (ROOT / "run.bat").read_text(encoding="utf-8")
    assert '-File "%~dp0run.ps1" %*' in content
    assert "-NoProfile -ExecutionPolicy Bypass" in content
    assert "set \"EXPOSUREIQ_EXIT_CODE=%ERRORLEVEL%\"" in content
    assert "exit /b %EXPOSUREIQ_EXIT_CODE%" in content
    assert "Set-ExecutionPolicy" not in content


@pytest.mark.skipif(os.name != "nt", reason="Native batch execution requires Windows")
def test_batch_help_from_another_directory(tmp_path):
    result = subprocess.run(
        f'cmd.exe /d /s /c ""{ROOT / "run.bat"}" help"',
        cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ExposureIQ Windows helper" in result.stdout


@pytest.mark.parametrize("name", ["run.ps1", "scripts/windows-install.ps1"])
def test_powershell_syntax(powershell, name):
    path = str(ROOT / name).replace("'", "''")
    result = subprocess.run(
        [powershell, "-NoProfile", "-Command",
         f"$tokens = $null; $errors = $null; "
         f"[System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$tokens, [ref]$errors) | Out-Null; "
         "if ($errors.Count) { $errors | Out-String | Write-Host; exit 1 }"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("arguments,code", [(("help",), 0), (("--help",), 0), (("unknown",), 2),
                                          (("scan",), 2), (("install", "unexpected"), 2),
                                          (("scan", "example.com", "--active", "--passive"), 2)])
def test_help_and_invalid_commands_never_install(helper, arguments, code):
    project, _, run = helper
    result = run(*arguments)
    assert result.returncode == code, result.stdout + result.stderr
    assert not (project / ".venv").exists()
    assert not calls(project, "launcher")


@pytest.mark.parametrize("launcher", ["py.exe", "python.exe", "python3.exe"])
def test_install_detects_python_and_does_not_launch_or_scan(helper, launcher):
    project, _, run = helper
    result = run("install", TEST_LAUNCHER=launcher)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (project / ".venv" / "Scripts" / "python.exe").exists()
    assert (project / ".venv" / ".windows-deps.sha256").read_text().strip()
    assert [call["args"] for call in calls(project, "pip")] == [
        ["install", "--upgrade", "pip"], ["install", "-e", f"{project}[dev]"],
    ]
    prefix = ["-3"] if launcher == "py.exe" else []
    assert calls(project, "launcher")[1]["args"] == prefix + ["-m", "venv", str(project / ".venv")]
    assert not calls(project, "cli")


def test_default_launch_uses_project_directory_and_restores_caller(helper):
    project, caller, run = helper
    result = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls(project, "cli")[0]["args"] == []
    assert all(Path(call["cwd"]) == project for call in calls(project, "pip") + calls(project, "cli"))
    assert Path((caller / "restored-location.txt").read_text(encoding="utf-8")) == caller


def test_demo_forwards_options_and_quoted_paths(helper):
    project, _, run = helper
    result = run("demo", "--plain", "-o", "demo output with spaces/")
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls(project, "cli")[0]["args"] == [
        "scan", "example.com", "--demo", "--plain", "-o", "demo output with spaces/",
    ]


@pytest.mark.parametrize("options,expected", [
    ([], ["--passive"]), (["--plain"], ["--plain", "--passive"]),
    (["--passive"], ["--passive"]), (["--active", "--plain"], ["--plain"]),
])
def test_scans_are_passive_unless_explicitly_active(helper, options, expected):
    project, _, run = helper
    result = run("scan", "example.com", *options)
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls(project, "cli")[0]["args"] == ["scan", "example.com", *expected]


def test_dependencies_are_cached_and_refreshed_after_manifest_change(helper):
    project, _, run = helper
    assert run("install").returncode == 0
    assert run("demo").returncode == 0
    assert len(calls(project, "pip")) == 2
    manifest = project / "pyproject.toml"
    manifest.write_text(manifest.read_text() + "# changed\n", encoding="utf-8")
    assert run("demo").returncode == 0
    assert len(calls(project, "pip")) == 4
    creations = [call for call in calls(project, "launcher") if call["args"][-3:-1] == ["-m", "venv"]]
    assert len(creations) == 1  # Doctor may check versions, but do not recreate a venv.


def test_failed_forced_install_invalidates_cache_and_never_launches(helper):
    project, _, run = helper
    assert run("install").returncode == 0
    result = run("install", FAKE_PIP_EXIT="9")
    assert result.returncode == 1
    assert "Command failed (exit 9)" in result.stderr
    assert not (project / ".venv" / ".windows-deps.sha256").read_text().strip()
    assert not calls(project, "cli")
    assert run("demo").returncode == 0
    assert len(calls(project, "pip")) == 5  # Successful install, failed refresh, retry.


@pytest.mark.parametrize("overrides", [{"TEST_LAUNCHER": ""}, {"FAKE_PYTHON_EXIT": "1"}])
def test_missing_or_unsupported_python_has_actionable_error(helper, overrides):
    project, _, run = helper
    result = run("demo", **overrides)
    assert result.returncode == 1
    assert "Python 3.10+ was not found" in result.stderr
    assert not (project / ".venv").exists()
    assert not calls(project, "pip")


def test_incompatible_existing_environment_is_preserved(helper):
    project, _, run = helper
    environment = project / ".venv"
    environment.mkdir()
    marker = environment / "keep-me.txt"
    marker.write_text("existing user work", encoding="utf-8")
    result = run("install")
    assert result.returncode == 1
    assert "nothing was deleted" in result.stderr
    assert marker.read_text() == "existing user work"
    assert not calls(project, "launcher")
    assert not calls(project, "pip")


@pytest.mark.parametrize("command,variable,code,kind,expected", [
    ("demo", "FAKE_CLI_EXIT", 7, "cli", ["scan", "example.com", "--demo"]),
    ("test", "FAKE_TEST_EXIT", 5, "pytest", ["-q"]),
])
def test_cli_and_test_exit_codes_are_preserved(helper, command, variable, code, kind, expected):
    project, _, run = helper
    result = run(command, **{variable: str(code)})
    assert result.returncode == code, result.stdout + result.stderr
    assert calls(project, kind)[0]["args"] == expected


def test_full_install_downloads_tools_and_makes_them_visible_to_cli(helper):
    project, caller, run = helper
    result = run("install")
    assert result.returncode == 0, result.stdout + result.stderr
    downloads = calls(project, "download")
    assert len(downloads) == 2
    assert any("subfinder_2.17.0_windows_amd64.zip" in call["args"][0] for call in downloads)
    assert any("nmap-7.993-setup.exe" in call["args"][0] for call in downloads)
    assert not calls(project, "cli")  # Installation never starts a scan.
    assert run("--version").returncode == 0
    cli = calls(project, "cli")[0]
    assert cli["args"] == ["--version"]
    assert Path(cli["subfinder"]).name == "subfinder.exe"
    assert str(Path(cli["subfinder"]).parent) in cli["path"]
    assert "Nmap" in cli["path"]
    restored = json.loads((caller / "restored-environment.json").read_text(encoding="utf-8"))
    assert restored["path"] != cli["path"]
    assert restored["subfinder"] == os.environ.get("SUBFINDER_PATH")


def test_python_only_install_does_not_install_network_tools(helper):
    project, _, run = helper
    result = run("install", "--python-only")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls(project, "pip")) == 2
    assert not calls(project, "download")
    assert not calls(project, "installer")
    assert not calls(project, "cli")


@pytest.mark.parametrize("options", [[], ["--python-only"]])
def test_explicit_install_bootstraps_python_if_missing(helper, options):
    project, _, run = helper
    result = run("install", *options, TEST_LAUNCHER="")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (project / ".venv" / "Scripts" / "python.exe").exists()
    installers = calls(project, "installer")
    assert len(installers) == (1 if options else 2)
    assert "python-3.14.10-amd64.exe" in installers[0]["args"][0]
    assert "InstallAllUsers=0" in installers[0]["args"]
    assert "PrependPath=0" in installers[0]["args"]
    assert any(argument.startswith('TargetDir="') for argument in installers[0]["args"])
    assert len(calls(project, "download")) == (1 if options else 3)
    assert not calls(project, "cli")


def test_doctor_without_python_does_not_install_or_create_environment(helper):
    project, _, run = helper
    result = run("doctor", TEST_LAUNCHER="")
    assert result.returncode == 1
    assert "[MISSING] Python" in result.stdout
    assert not (project / ".venv").exists()
    assert not calls(project, "download")
    assert not calls(project, "installer")
    assert not calls(project, "pip")
    assert not calls(project, "cli")


def test_doctor_works_with_legacy_native_argument_handling(helper):
    project, _, run = helper
    assert run("install").returncode == 0
    result = run("doctor", TEST_NATIVE_ARGUMENTS="Legacy")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[OK] Project Python packages found" in result.stdout
    assert "[OK] Nmap" in result.stdout
    assert "[OK] Subfinder" in result.stdout
    assert len(calls(project, "download")) == 2  # Doctor never downloads anything.


def test_doctor_reuses_project_python_without_a_launcher_on_path(helper):
    project, _, run = helper
    assert run("install").returncode == 0
    result = run("doctor", TEST_LAUNCHER="")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[OK] Python 3.10+" in result.stdout
    assert len(calls(project, "download")) == 2


def test_doctor_reports_missing_python_packages_without_reinstalling(helper):
    project, _, run = helper
    assert run("install").returncode == 0
    (project / "rich.py").unlink()
    result = run("doctor")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Missing Python packages: rich" in result.stdout
    assert len(calls(project, "pip")) == 2
    assert len(calls(project, "download")) == 2
    assert not calls(project, "cli")


def test_launcher_auto_install_is_disabled_temporarily(helper):
    project, caller, run = helper
    result = run("demo", PYTHON_MANAGER_AUTOMATIC_INSTALL="true")
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(call["auto_install"] == "false" for call in calls(project, "launcher") + calls(project, "cli"))
    restored = json.loads((caller / "restored-environment.json").read_text(encoding="utf-8"))
    assert restored["auto_install"] == "true"
    assert not calls(project, "download")


@pytest.mark.parametrize("overrides,error", [
    ({"FAKE_DOWNLOAD_ERROR": "1"}, "Download failed"),
    ({"FAKE_INSTALL_EXIT": "9"}, "Installer failed or was cancelled"),
    ({"FAKE_NMAP_INCOMPLETE": "1"}, "Nmap is not ready after installation"),
])
def test_failed_install_is_not_reported_as_ready(helper, overrides, error):
    project, _, run = helper
    result = run("install", **overrides)
    assert result.returncode == 1
    assert error in result.stderr
    assert "==> Ready." not in result.stdout
    assert not calls(project, "cli")

import shutil
import subprocess
import xml.etree.ElementTree as ET

from exposureiq.discovery.scope import is_in_scope


def scan_ports(target: str) -> list[dict]:
    """
    Scan the 100 most common TCP ports on an authorized target.

    Args:
        target: An authorized hostname or IP address.

    Returns:
        A list of dictionaries containing port, protocol, and service.
        Only open ports are returned, sorted by port number.

    Raises:
        ValueError: If the target is outside the authorized scope.
        RuntimeError: If Nmap is missing, fails, or returns invalid XML.
        TimeoutError: If the scan exceeds 120 seconds.
    """
    if not is_in_scope(target):
        raise ValueError(
            f"Target '{target}' is not in the authorized scope. "
            "Add an approved target to scope.txt before scanning."
        )

    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and ensure it is in PATH."
        )

    command = [
        nmap_path,
        "-sT",
        "-Pn",
        "--top-ports", "100",
        "-oX", "-",
        target.strip(),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Nmap scan timed out after 120 seconds for {target}."
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Could not start Nmap: {exc}") from exc

    if result.returncode != 0:
        details = result.stderr.strip() or "No additional details."
        raise RuntimeError(f"Nmap failed: {details}")

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned invalid XML output.") from exc

    host = root.find("host")
    if host is None:
        return []

    status = host.find("status")
    if status is not None and status.get("state") == "down":
        return []

    open_ports = []

    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        service = port.find("service")

        open_ports.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol", ""),
            "service": (
                service.get("name", "unknown")
                if service is not None
                else "unknown"
            ),
        })

    return sorted(open_ports, key=lambda item: item["port"])

# Import json to convert Python dictionaries into JSON files and back.
import json

# Import ipaddress to check that IP addresses are real IP addresses.
import ipaddress

# Import datetime to get the current time.
from datetime import datetime, timezone

# Import Path to work with file paths and create directories.
from pathlib import Path


# Define the version of the findings format that new scans are written with.
SCHEMA_VERSION = "0.2"

# Every format version that can still be saved and loaded.
# Old 0.1 files have no technologies or findings, and they must keep working.
SUPPORTED_VERSIONS = {"0.1", "0.2"}

# The only severity levels a finding may use.
ALLOWED_SEVERITIES = ("low", "medium", "high")

# Text fields that every finding must have (non-empty strings).
FINDING_TEXT_FIELDS = ("id", "rule", "check", "title", "detail", "recommendation")


def _utc_now():
    # Get the current date and time using the UTC timezone.
    now = datetime.now(timezone.utc)

    # Convert the time to ISO 8601 format.
    # Replace +00:00 with Z to indicate UTC.
    return now.isoformat(timespec="seconds").replace("+00:00", "Z")


# Public name, so other modules (for example the command line) can use it.
utc_now = _utc_now


def build_scan(target: str, assets: list, started_at: str = None) -> dict:
    # Create a complete scan result from the target and discovered assets.
    # target is the domain being scanned.
    # assets is a list containing subdomains, IP addresses, and port results.
    # started_at is the UTC time the scan really began (same format as utc_now()).
    # If it is not given, the current time is used.

    # Check that the target is a non-empty string.
    if not isinstance(target, str) or not target.strip():
        # Stop execution if the target is invalid.
        raise ValueError("target must be a non-empty string.")

    # Check that assets is a Python list.
    if not isinstance(assets, list):
        # Stop execution if assets has the wrong type.
        raise ValueError("assets must be a list.")

    # Use the real start time if one was given, otherwise use the current time.
    if started_at is None:
        started_at = _utc_now()
    elif not isinstance(started_at, str) or not started_at.strip():
        raise ValueError("started_at must be a non-empty string.")

    # Generate a scan ID from the UTC timestamp.
    # Replace colons so the ID is easier to use in filenames.
    scan_id = started_at.replace(":", "-")

    # Return all scan information as one Python dictionary.
    return {
        # Record which findings format version this scan uses.
        "schema_version": SCHEMA_VERSION,

        # Store the identifier for this scan.
        "scan_id": scan_id,

        # Store the domain being scanned.
        "target": target.strip(),

        # Store the UTC time when the scan started.
        "started_at": started_at,

        # Store the subdomains, IP addresses, and port findings.
        "assets": assets,
    }


def _validate_scan(scan: dict) -> None:
    # Validate the scan before saving it or returning loaded data.
    # The leading underscore indicates an internal helper function.

    # Make sure the scan is represented by a dictionary.
    if not isinstance(scan, dict):
        # Raise an error if the scan is not a dictionary.
        raise ValueError("Invalid scan: expected a JSON object.")

    # Define every field that must exist at the top level.
    required_fields = {
        "schema_version",
        "scan_id",
        "target",
        "started_at",
        "assets",
    }

    # Find required fields that are missing from the scan.
    missing = required_fields - scan.keys()

    # If any required fields are missing, report their names.
    if missing:
        raise ValueError(
            f"Invalid scan: missing required fields: "
            f"{', '.join(sorted(missing))}."
        )

    # Reject files that use an unsupported findings format version.
    # A list is not hashable, so check the type before the set lookup.
    if (
        not isinstance(scan["schema_version"], str)
        or scan["schema_version"] not in SUPPORTED_VERSIONS
    ):
        raise ValueError(
            f"Unsupported schema_version: {scan['schema_version']!r}. "
            f"Supported versions: {', '.join(sorted(SUPPORTED_VERSIONS))}."
        )

    # These fields must all contain non-empty strings.
    for field in ("scan_id", "target", "started_at"):
        # Check both the field's type and whether it contains text.
        if not isinstance(scan[field], str) or not scan[field].strip():
            # Report which field has an invalid value.
            raise ValueError(
                f"Invalid scan: '{field}' must be a non-empty string."
            )

    # The assets field must contain a list of discovered hosts.
    if not isinstance(scan["assets"], list):
        raise ValueError("Invalid scan: 'assets' must be a list.")

    # Check each discovered host in the assets list.
    # enumerate provides both the item's position and its value.
    for asset_index, asset in enumerate(scan["assets"]):
        # Build a useful label for errors about this host.
        prefix = f"Invalid scan: assets[{asset_index}]"

        # Each host must be represented by a dictionary.
        if not isinstance(asset, dict):
            raise ValueError(f"{prefix} must be an object.")

        # Every host must include its hostname and IP list.
        for field in ("host", "ips"):
            # Check whether the required field exists.
            if field not in asset:
                raise ValueError(
                    f"{prefix} is missing required field '{field}'."
                )

        # Check that the hostname is a non-empty string.
        if not isinstance(asset["host"], str) or not asset["host"].strip():
            raise ValueError(
                f"{prefix}.host must be a non-empty string."
            )

        # Each host's IP addresses must be stored in a list.
        if not isinstance(asset["ips"], list):
            raise ValueError(f"{prefix}.ips must be a list.")

        # Check each IP address entry belonging to this host.
        for ip_index, ip_entry in enumerate(asset["ips"]):
            # Build a label that identifies the specific IP entry.
            ip_prefix = f"{prefix}.ips[{ip_index}]"

            # Each IP entry must be represented by a dictionary.
            if not isinstance(ip_entry, dict):
                raise ValueError(f"{ip_prefix} must be an object.")

            # Each IP entry must include the IP and its port findings.
            for field in ("ip", "open_ports"):
                # Reject entries missing either required field.
                if field not in ip_entry:
                    raise ValueError(
                        f"{ip_prefix} is missing required field '{field}'."
                    )

            # Make sure the IP address field is a non-empty string.
            if (
                not isinstance(ip_entry["ip"], str)
                or not ip_entry["ip"].strip()
            ):
                raise ValueError(
                    f"{ip_prefix}.ip must be a non-empty string."
                )

            # The IP address must be a real IPv4 or IPv6 address.
            try:
                ipaddress.ip_address(ip_entry["ip"].strip())
            except ValueError:
                raise ValueError(
                    f"{ip_prefix}.ip is not a valid IP address: "
                    f"{ip_entry['ip']!r}."
                ) from None

            # Port findings must be stored in a list.
            if not isinstance(ip_entry["open_ports"], list):
                raise ValueError(
                    f"{ip_prefix}.open_ports must be a list."
                )

            # Check every port reported for this IP address.
            for port_index, port_entry in enumerate(ip_entry["open_ports"]):
                # Build a label identifying the specific port entry.
                port_prefix = f"{ip_prefix}.open_ports[{port_index}]"

                # Each port must be represented by a dictionary.
                if not isinstance(port_entry, dict):
                    raise ValueError(
                        f"{port_prefix} must be an object."
                    )

                # Every port entry must include these three fields.
                for field in ("port", "protocol", "service"):
                    # Report an error if any field is missing.
                    if field not in port_entry:
                        raise ValueError(
                            f"{port_prefix} is missing required field "
                            f"'{field}'."
                        )

                # Extract the port number for validation.
                port_number = port_entry["port"]

                # A Boolean is technically an integer subclass in Python,
                # so reject True and False explicitly.
                if (
                    isinstance(port_number, bool)
                    or not isinstance(port_number, int)
                    or not 1 <= port_number <= 65535
                ):
                    # Port numbers must be valid TCP/UDP port numbers.
                    raise ValueError(
                        f"{port_prefix}.port must be an integer "
                        "between 1 and 65535."
                    )

                # The protocol and service must both contain text.
                for field in ("protocol", "service"):
                    # Reject missing-quality values such as empty strings.
                    if (
                        not isinstance(port_entry[field], str)
                        or not port_entry[field].strip()
                    ):
                        raise ValueError(
                            f"{port_prefix}.{field} must be a "
                            "non-empty string."
                        )

        # Format 0.2: both lists are optional, but if present they must be valid.
        if "technologies" in asset:
            _validate_technologies(asset["technologies"], prefix)

        if "findings" in asset:
            _validate_findings(asset["findings"], prefix)


def _validate_technologies(technologies, prefix: str) -> None:
    # Check the optional list of technologies found on one asset.
    # prefix is the error label of the asset, for example "Invalid scan: assets[0]".

    # The technologies field must be a list.
    if not isinstance(technologies, list):
        raise ValueError(f"{prefix}.technologies must be a list.")

    for index, tech in enumerate(technologies):
        # Build a label that identifies this technology entry.
        tech_prefix = f"{prefix}.technologies[{index}]"

        # Each technology must be an object.
        if not isinstance(tech, dict):
            raise ValueError(f"{tech_prefix} must be an object.")

        # name, version and source must all exist.
        for field in ("name", "version", "source"):
            if field not in tech:
                raise ValueError(
                    f"{tech_prefix} is missing required field '{field}'."
                )

        # name and source must contain text.
        for field in ("name", "source"):
            if not isinstance(tech[field], str) or not tech[field].strip():
                raise ValueError(
                    f"{tech_prefix}.{field} must be a non-empty string."
                )

        # The version must be a string, but an empty string is allowed
        # (we sometimes know the product but not its version).
        if not isinstance(tech["version"], str):
            raise ValueError(f"{tech_prefix}.version must be a string.")


def _validate_findings(findings, prefix: str) -> None:
    # Check the optional list of findings (security problems) on one asset.

    # The findings field must be a list.
    if not isinstance(findings, list):
        raise ValueError(f"{prefix}.findings must be a list.")

    for index, finding in enumerate(findings):
        # Build a label that identifies this finding.
        finding_prefix = f"{prefix}.findings[{index}]"

        # Each finding must be an object.
        if not isinstance(finding, dict):
            raise ValueError(f"{finding_prefix} must be an object.")

        # These fields are required in every finding.
        for field in FINDING_TEXT_FIELDS + ("severity",):
            if field not in finding:
                raise ValueError(
                    f"{finding_prefix} is missing required field '{field}'."
                )

        # These fields must contain text.
        for field in FINDING_TEXT_FIELDS:
            if not isinstance(finding[field], str) or not finding[field].strip():
                raise ValueError(
                    f"{finding_prefix}.{field} must be a non-empty string."
                )

        # Severity can only be one of the three allowed levels.
        if (
            not isinstance(finding["severity"], str)
            or finding["severity"] not in ALLOWED_SEVERITIES
        ):
            raise ValueError(
                f"{finding_prefix}.severity must be low, medium or high."
            )

        # Optional ip: if present it must be a real IPv4 or IPv6 address.
        if "ip" in finding:
            try:
                if not isinstance(finding["ip"], str):
                    raise ValueError
                ipaddress.ip_address(finding["ip"].strip())
            except ValueError:
                raise ValueError(
                    f"{finding_prefix}.ip is not a valid IP address: "
                    f"{finding['ip']!r}."
                ) from None

        # Optional port: if present it must be an integer from 1 to 65535.
        # Reject True and False, because bool is a subclass of int in Python.
        if "port" in finding:
            port = finding["port"]
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise ValueError(
                    f"{finding_prefix}.port must be an integer "
                    "between 1 and 65535."
                )


def save_scan(scan: dict, path: str) -> None:
    # Save a scan dictionary to a JSON file.
    # scan is the findings dictionary.
    # path is the destination filename, including its directory.

    # Validate the data before writing anything to the file.
    _validate_scan(scan)

    # Convert the supplied path into a Path object.
    file_path = Path(path)

    # Create the parent directories if they do not already exist.
    # parents=True allows multiple missing directory levels.
    # exist_ok=True prevents an error if the directory already exists.
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Open the destination file for writing using UTF-8 encoding.
    with file_path.open("w", encoding="utf-8") as file:
        # Convert the Python dictionary into readable JSON.
        json.dump(
            scan,                 # The scan data to serialize.
            file,                 # The destination file object.
            indent=2,             # Use two spaces for each indentation level.
            ensure_ascii=False,   # Preserve non-ASCII characters as readable text.
        )

        # Add a final newline to keep the JSON file tidy.
        file.write("\n")


def load_scan(path: str) -> dict:
    # Load scan results from a JSON file and validate them.
    # Return the data as a Python dictionary.

    # Convert the supplied filename into a Path object.
    file_path = Path(path)

    # Try to open and parse the JSON file.
    try:
        # Open the file for reading with UTF-8 encoding.
        with file_path.open("r", encoding="utf-8") as file:
            # Parse JSON text into Python dictionaries and lists.
            scan = json.load(file)

    # Handle the case where the requested file does not exist.
    except FileNotFoundError as exc:
        # Raise a clearer error while preserving the original cause.
        raise FileNotFoundError(
            f"Scan file not found: {file_path}"
        ) from exc

    # Handle malformed JSON, such as missing commas or brackets.
    except json.JSONDecodeError as exc:
        # Include the file location, line number, and column number.
        raise ValueError(
            f"Broken JSON in '{file_path}' at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc

    # Handle files that cannot be decoded as UTF-8.
    except UnicodeDecodeError as exc:
        # Explain that the file encoding is invalid.
        raise ValueError(
            f"Invalid UTF-8 encoding in scan file: {file_path}"
        ) from exc

    # Check the loaded data's version, fields, and nested structure.
    _validate_scan(scan)

    # Return the validated findings to the calling program.
    return scan

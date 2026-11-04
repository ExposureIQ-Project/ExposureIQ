"""Domain folders and read-only discovery of current and legacy JSON files."""

from pathlib import Path

RESULTS_ROOT = Path("results")


def domain_directory(root: str | Path, domain: str) -> Path:
    """Use one normalized domain folder, without adding it twice."""
    from exposureiq.discovery.subdomains import normalize_domain

    wanted = normalize_domain(domain)
    directory = Path(root)
    return directory if directory.name.lower() == wanted else directory / wanted


def scan_output_path(domain: str, filename: str, output: str | None = None) -> Path:
    """Explicit JSON filenames stay exact; directory outputs group by domain."""
    if output and Path(output).suffix.lower() == ".json":
        return Path(output)
    return domain_directory(output or RESULTS_ROOT, domain) / filename


def saved_json_paths(directory: str | Path, domain: str | None = None) -> list[Path]:
    """Read flat files and one level of domain folders; never move old files.

    A domain-specific lookup also reads legacy files beside its domain folder.
    It does not walk other domain folders or arbitrary nested directories.
    """
    root = Path(directory)
    if domain is None:
        return sorted(set(root.glob("*.json")) | set(root.glob("*/*.json")))

    folder = domain_directory(root, domain)
    directories = {root, folder}
    if folder == root:
        directories.add(root.parent)
    return sorted({path for parent in directories for path in parent.glob("*.json")})

"""AI preferences and disposable caches must never live in the source tree."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def outside_project(path) -> bool:
    try:
        candidate = Path(path)
        return not (candidate.absolute().is_relative_to(PROJECT_ROOT)
                    or candidate.resolve().is_relative_to(PROJECT_ROOT))
    except (OSError, ValueError, RuntimeError):
        return False

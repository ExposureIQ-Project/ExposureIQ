"""Web-only checks for explicitly confirmed names, preserving one scan snapshot."""

import copy
import time

from exposureiq import output
from exposureiq.tui.control import ScanControl, cancellable_checks, observe_checks
from exposureiq.tui.scan import _demo_checks
from exposureiq.tui.user_scope import MAX_HOSTS, eligible_hosts, remember_scan


def rerun_hosts(result: dict, names: list, stages, report, control: ScanControl) -> dict:
    """Sequential (one request at a time), same scope and runner, never ports/DNS."""
    updated = copy.deepcopy(result)
    domain = result["target"]
    allowed_names = set(eligible_hosts(domain, names)[:MAX_HOSTS])
    # A name must also be an actual saved asset and a scope-skipped host.
    pending = [asset for asset in updated["assets"]
               if asset["host"] in allowed_names and asset["host"] in result.get("skipped_hosts", [])]
    control.check()
    if updated.get("saved_to") and (updated.get("snapshot") is None or stages.save_scan is None):
        raise ValueError("Cannot update the saved JSON without the original snapshot and storage module.")
    gate = stages.demo_scope if result.get("demo") else stages.load_scope()
    checks = _demo_checks if result.get("demo") else stages.load_checks()
    next_id = 1
    for asset in updated["assets"]:
        for finding in asset.get("findings", []):
            try:
                next_id = max(next_id, int(finding["id"].removeprefix("F-")) + 1)
            except (ValueError, KeyError):
                continue
    authorized, attempted = [], []
    clock = time.monotonic()

    def progress(host, state, message):
        control.check()
        report({"kind": "host_progress", "host": host, "state": state, "message": message})

    for asset in pending:
        progress(asset["host"], "waiting", f"{asset['host']}: waiting for web checks")
    for asset in pending:
        host = asset["host"]
        control.check()
        try:
            permitted = gate is not None and gate(host) is True
        except Exception:
            permitted = False
        if not permitted:
            updated["host_states"][host] = "failed: scope could not be verified"
            message = f"{host}: scope could not be verified; no requests sent"
            updated.setdefault("warnings", []).append(message)
            progress(host, "failed", message)
            continue
        authorized.append(host)
        if checks is None:
            updated["host_states"][host] = "failed: web checks unavailable"
            message = f"{host}: web checks are unavailable; no requests sent"
            updated.setdefault("warnings", []).append(message)
            progress(host, "failed", message)
            continue
        attempted.append(host)
        progress(host, "checking", f"{host}: checking technologies, headers, and HTTPS/certificate")
        observed = {"attempted": False, "answered": None, "warnings": []}
        try:
            with observe_checks(checks) as observed, cancellable_checks(checks, control):
                checked = checks([copy.deepcopy(asset)])
            control.check()
            if not isinstance(checked, list) or len(checked) != 1 or not isinstance(checked[0], dict) \
                    or checked[0].get("host") != host:
                raise ValueError("The check runner did not return an asset.")
            # Only web annotations change. Original names, IPs and ports stay intact.
            asset["technologies"] = checked[0].get("technologies", [])
            asset["findings"] = checked[0].get("findings", [])
            for finding in asset.get("findings", []):
                finding["id"] = f"F-{next_id:04d}"
                next_id += 1
            failed, message = output.web_check_status(host, observed)
            updated["host_states"][host] = "failed: see warning" if failed else "done"
            progress(host, "failed" if failed else "done", message)
            if failed:
                updated.setdefault("warnings", []).append(message)
        except Exception as error:
            saved_asset = next(item for item in result["assets"] if item["host"] == host)
            asset["technologies"] = copy.deepcopy(saved_asset.get("technologies", []))
            asset["findings"] = copy.deepcopy(saved_asset.get("findings", []))
            updated["host_states"][host] = "failed: see warning"
            message = f"{host}: web checks failed ({error})"
            updated.setdefault("warnings", []).append(message)
            progress(host, "failed", message)
        finally:
            updated.setdefault("warnings", []).extend(observed["warnings"])
    control.check()
    updated["skipped_hosts"] = [host for host in result.get("skipped_hosts", []) if host not in authorized]
    updated["phase_counts"]["Scope"] += len(authorized)
    if authorized:
        updated["phase_states"]["Scope"] = "done"
        if updated.get("mode") == "passive":
            updated["mode"] = "partial"
            updated["mode_detail"] = ("Confirmed host names were web-checked; no port scans ran. "
                                      "Run a new scan for full mode.")
    updated["phase_counts"]["Web checks"] += len(attempted)
    updated["phase_times"]["Web checks"] += time.monotonic() - clock
    if attempted:
        updated["phase_states"]["Web checks"] = "done"
    updated["elapsed"] += time.monotonic() - clock
    snapshot = updated.get("snapshot")
    if updated.get("saved_to") and snapshot is not None and stages.save_scan is not None:
        snapshot["assets"] = updated["assets"]
        control.check()
        # Keep schema_version, scan_id, target, and started_at exactly as saved.
        stages.save_scan(snapshot, updated["saved_to"])
        try:
            remember_scan(updated)
        except (OSError, ValueError) as error:
            updated.setdefault("warnings", []).append(f"Could not update last-scan record: {error}")
        report({"kind": "log", "level": "ok", "message": f"Updated the same JSON: {updated['saved_to']}"})
    report({"kind": "rerun_result", "result": updated})
    return updated

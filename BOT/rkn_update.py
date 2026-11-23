from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from . import antiddos


def main() -> int:
    state_dir = Path(os.environ.get("OBHOD_STATE_DIR", "/var/lib/obhod"))
    if not state_dir.is_absolute() or ".." in state_dir.parts:
        print("invalid state directory", file=sys.stderr)
        return 2
    try:
        raw = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("state unavailable; existing protection left intact", file=sys.stderr)
        return 2
    if not isinstance(raw, dict):
        print("invalid state", file=sys.stderr)
        return 2
    policy = antiddos.Policy.from_dict(raw.get("ddos"))
    if not policy.enabled or not policy.rkn_enabled:
        print("RKN update skipped: disabled")
        return 0
    source = Path(__file__).resolve().parent.parent / "Storage" / "remote" / "ddos_agent.py"
    try:
        check = subprocess.run([sys.executable, str(source), "status"], capture_output=True, timeout=60, check=False)
        response = json.loads(check.stdout.decode("utf-8"))
        if check.returncode != 0 or not isinstance(response, dict) or not response.get("ok"):
            raise ValueError("status unavailable")
        status = antiddos.Status.from_dict(response.get("data"))
        digest = status.policy_sha256
        if (not status.installed or status.transaction_state != "none" or status.table_inspection == "unknown" or not status.table or not status.enabled or antiddos.firewall_policy_differs(policy, status.policy) or status.saved_policy_consistency in ("mismatch", "unknown") or status.live_rate_consistency in ("mismatch", "unknown") or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("firewall policy needs review")
    except (OSError, ValueError, subprocess.SubprocessError):
        print("firewall policy unavailable or inconsistent; existing protection left intact", file=sys.stderr)
        return 2
    extra = policy.allow_entries()
    for parent, key in (("ssh", "host"), ("xray", "sub_address")):
        data = raw.get(parent)
        if isinstance(data, dict):
            extra.append(str(data.get(key, "")))
    ft = raw.get("freeturn")
    if isinstance(ft, dict) and isinstance(ft.get("config"), dict):
        extra.append(str(ft["config"].get("host", "")))
    extra = antiddos.exempt_entries(extra)
    try:
        v4, v6, count, errors = antiddos.fetch_rkn_subnets(custom_sources=policy.custom_sources, disabled_sources=policy.disabled_sources, extra_protected=extra, cache_path=state_dir / "rkn_sources_cache.json")
    except (antiddos.DDoSerror, OSError, ValueError):
        print("source configuration or cache failed; existing protection left intact", file=sys.stderr)
        return 2
    try:
        latest = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
        current = antiddos.Policy.from_dict(latest.get("ddos") if isinstance(latest, dict) else {})
    except (OSError, ValueError):
        print("state changed or unavailable; update cancelled", file=sys.stderr)
        return 2
    if antiddos.firewall_policy_differs(current, policy) or (current.custom_sources, current.disabled_sources) != (policy.custom_sources, policy.disabled_sources):
        print("policy changed during update; update cancelled", file=sys.stderr)
        return 2
    args = [sys.executable, str(source), "rkn-sync", "--rkn_zhex=-", "--expected_policy_sha=" + digest]
    if any("(no cache)" in item or "(cached)" not in item for item in errors):
        args.append("--preserve_existing=1")
    try:
        result = subprocess.run(args, input=antiddos.encode_rkn_zhex(v4, v6).encode("ascii"), capture_output=True, timeout=240, check=False)
        response = json.loads(result.stdout.decode("utf-8"))
    except (OSError, ValueError, subprocess.SubprocessError):
        print("agent invocation failed; inspect service journal", file=sys.stderr)
        return 2
    if result.returncode != 0 or not isinstance(response, dict) or not response.get("ok"):
        print("agent did not apply the update", file=sys.stderr)
        return 2
    print("source updates: %d; failures: %d; IPv4: %d; IPv6: %d" % (count, len(errors), len(v4), len(v6)))
    for item in errors:
        print(item[:160], file=sys.stderr)
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

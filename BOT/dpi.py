from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

PROC_MPTCP = "/proc/sys/net/mptcp/enabled"
PROC_MIGRATE = "/proc/sys/net/ipv4/tcp_migrate_req"
PROC_RELEASE = "/proc/sys/kernel/osrelease"
MIN_CORE = (26, 10, 31)
MIN_CORE_TAG = "v26.10.31"
ADVISORY = "CVE-2026-98432"
FIXED_KERNELS = {
    (6, 1): 190,
    (6, 12): 113,
}
KERNEL_FIXED = "fixed"
KERNEL_OLD = "old"
KERNEL_UNKNOWN = "unknown"
MASS_FINGERPRINTS = ("chrome",)
SYNTHETIC_FINGERPRINTS = ("randomized", "randomizednoalpn")
HOSTER_MARKERS = (
    "selectel",
    "yandex",
    "vk cloud",
    "timeweb",
    "aeza",
    "beget",
    "firstvds",
    "ihor",
    "hostkey",
    "majordomo",
    "reg.ru",
    "smartape",
    "cloud4y",
    "justhost",
    "vdsina",
    "ruvds",
    "netangels",
    "servercore",
    "vscale",
)
RELEASE_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass
class Finding:
    key: str
    level: str
    value: str = ""

    def blocking(self) -> bool:
        return self.level == "bad"


@dataclass
class Kernel:
    release: str = ""
    fixed: bool = False
    known: bool = True
    series: str = ""
    mptcp: int = -1
    migrate: int = -1
    listeners: int = -1
    listener_ports: str = ""
    error: str = ""


@dataclass
class Report:
    kernel: Kernel = field(default_factory=Kernel)
    core: str = ""
    core_ok: bool = False
    fingerprints: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    asn: str = ""
    organisation: str = ""
    country: str = ""
    hoster: str = ""
    findings: list[Finding] = field(default_factory=list)
    at: float = 0.0

    def level(self) -> str:
        if any(item.level == "bad" for item in self.findings):
            return "bad"
        if any(item.level == "warn" for item in self.findings):
            return "warn"
        return "ok"

    def by_key(self, key: str) -> Finding | None:
        for item in self.findings:
            if item.key == key:
                return item
        return None

    def keys(self) -> list[str]:
        return [item.key for item in self.findings]


def read_int(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return int(str(handle.read()).strip() or "-1")
    except (OSError, ValueError):
        return -1


def kernel_release() -> str:
    try:
        with open(PROC_RELEASE, "r", encoding="utf-8") as handle:
            text = str(handle.read()).strip()
            if text:
                return text
    except OSError:
        pass
    return str(os.uname().release or "")


def kernel_status(release: str) -> tuple[str, str]:
    match = RELEASE_RE.match(str(release or ""))
    if not match:
        return KERNEL_UNKNOWN, ""
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3) or 0)
    series = "%d.%d" % (major, minor)
    floor = FIXED_KERNELS.get((major, minor))
    if floor is None:
        return KERNEL_UNKNOWN, series
    return (KERNEL_FIXED if patch >= floor else KERNEL_OLD), series


def kernel_fixed(release: str) -> tuple[bool, str]:
    status, series = kernel_status(release)
    return status == KERNEL_FIXED, series


def mptcp_listeners(timeout: float = 6.0) -> tuple[int, str]:
    binary = shutil.which("ss")
    if not binary:
        return -1, ""
    try:
        proc = subprocess.run([binary, "-Mln"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    lines = [line.strip() for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    rows = [line for line in lines[1:] if line]
    ports = []
    for line in rows:
        parts = line.split()
        for part in parts:
            if part.count(":") == 1 and part.rsplit(":", 1)[-1].isdigit():
                ports.append(part.rsplit(":", 1)[-1])
                break
    return len(rows), ", ".join(sorted(set(ports))[:6])


def kernel_state(release: str = "") -> Kernel:
    release = release or kernel_release()
    status, series = kernel_status(release)
    count, ports = mptcp_listeners()
    return Kernel(
        release=release,
        fixed=status == KERNEL_FIXED,
        known=status != KERNEL_UNKNOWN,
        series=series,
        mptcp=read_int(PROC_MPTCP),
        migrate=read_int(PROC_MIGRATE),
        listeners=count,
        listener_ports=ports,
    )


def core_tuple(tag: str) -> tuple[int, int, int]:
    numbers = re.findall(r"[0-9]+", str(tag or ""))
    if len(numbers) < 3:
        return (0, 0, 0)
    return (int(numbers[0]), int(numbers[1]), int(numbers[2]))


def core_ok(tag: str) -> bool:
    numbers = core_tuple(tag)
    if numbers == (0, 0, 0):
        return False
    return numbers >= MIN_CORE


def hoster_of(organisation: str, asn: str = "") -> str:
    haystack = ("%s %s" % (organisation, asn)).lower()
    for marker in HOSTER_MARKERS:
        if marker in haystack:
            return marker
    return ""


def fingerprint_list(items: Any) -> list[str]:
    out: list[str] = []
    for item in items or []:
        name = str(item or "").strip().lower()
        if name and name not in out:
            out.append(name)
    return out


def assess(
    fingerprints: Any = None,
    networks: Any = None,
    core: str = "",
    asn: str = "",
    organisation: str = "",
    country: str = "",
    kernel: Kernel | None = None,
) -> Report:
    state = kernel if kernel is not None else kernel_state()
    marks = fingerprint_list(fingerprints)
    kinds = fingerprint_list(networks)
    report = Report(
        kernel=state,
        core=str(core or ""),
        core_ok=core_ok(core),
        fingerprints=marks,
        networks=kinds,
        asn=str(asn or ""),
        organisation=str(organisation or ""),
        country=str(country or ""),
        hoster=hoster_of(organisation, asn),
        at=time.time(),
    )
    findings = report.findings
    if not state.release:
        findings.append(Finding("kernel_unknown", "warn", ""))
    elif not state.known:
        findings.append(Finding("kernel_untracked", "warn", state.release))
    elif not state.fixed:
        findings.append(Finding("kernel_old", "bad", state.release))
    if state.mptcp == 1:
        findings.append(Finding("mptcp_on", "warn", ""))
    if state.migrate == 1:
        findings.append(Finding("migrate_on", "warn", ""))
    if state.listeners > 0:
        findings.append(Finding("mptcp_listener", "bad", state.listener_ports or str(state.listeners)))
    if state.release and state.fixed:
        findings.append(Finding("kernel_fixed", "ok", state.release))
    if report.core and not report.core_ok:
        findings.append(Finding("core_old", "bad", report.core))
    if report.core and report.core_ok:
        findings.append(Finding("core_fixed", "ok", report.core))
    for name in marks:
        if name in MASS_FINGERPRINTS:
            findings.append(Finding("fp_mass", "warn", name))
        if name in SYNTHETIC_FINGERPRINTS:
            findings.append(Finding("fp_synthetic", "bad", name))
    if report.hoster:
        findings.append(Finding("hoster_marked", "warn", report.hoster))
    if str(country or "").upper() == "RU":
        findings.append(Finding("country_ru", "warn", str(country)))
    if "xhttp" in kinds and "raw" not in kinds:
        findings.append(Finding("xhttp_only", "warn", ""))
    return report


def nft_rule() -> str:
    return (
        "table inet cve_2026_98432 {\n"
        "  chain input {\n"
        "    type filter hook input priority -310; policy accept;\n"
        "    ip protocol tcp ip hdrlength > 5 counter drop\n"
        "  }\n"
        "}"
    )


def sysctl_line() -> str:
    return "net.mptcp.enabled=0\nnet.ipv4.tcp_migrate_req=0"


def summary(report: Report) -> dict[str, Any]:
    return {
        "level": report.level(),
        "kernel": report.kernel.release,
        "kernel_fixed": report.kernel.fixed,
        "mptcp": report.kernel.mptcp,
        "listeners": report.kernel.listeners,
        "core": report.core,
        "core_ok": report.core_ok,
        "fingerprints": ",".join(report.fingerprints),
        "hoster": report.hoster,
        "findings": report.keys(),
    }


def fix_text() -> str:
    return "\n".join(
        [
            "# host wide, takes effect immediately, breaks nothing that uses plain tcp",
            "sysctl -w net.mptcp.enabled=0",
            "sysctl -w net.ipv4.tcp_migrate_req=0",
            "printf '%s\\n' 'net.mptcp.enabled=0' 'net.ipv4.tcp_migrate_req=0' > /etc/sysctl.d/99-no-mptcp.conf",
            "",
            "# interim filter while the kernel is still old, delete it after the reboot",
            "nft -f /etc/nftables.d/cve-2026-98432.nft",
            "nft list table inet cve_2026_98432",
            "nft delete table inet cve_2026_98432",
            "",
            "# verify",
            "uname -r",
            "cat /proc/sys/net/mptcp/enabled",
            "ss -Mlnp   # no -t flag, the -t form hides mptcp sockets",
            "xray version",
        ]
    )


def collect(inbounds: Any = None, core_book: Any = None) -> tuple[list[str], list[str], str]:
    marks: list[str] = []
    networks: list[str] = []
    for item in inbounds or []:
        flow = str(getattr(item, "fingerprint", "") or "").strip()
        security = str(getattr(item, "security", "") or "").strip().lower()
        network = str(getattr(item, "network", "") or "").strip().lower()
        if security == "reality" and flow and flow not in marks:
            marks.append(flow)
        if network and network not in networks:
            networks.append(network)
    version = ""
    if isinstance(core_book, dict):
        version = str(core_book.get("version", "") or "")[:24]
    return marks, networks, version


def quote_summary(report: Report) -> str:
    if report is None:
        return "empty"
    return "%s %s %s" % (report.level(), report.kernel.release, ",".join(report.keys()))

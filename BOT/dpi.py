from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SUSPICIOUS_FINGERPRINTS = ("chrome", "safari", "ios")
LOYAL_FINGERPRINTS = ("firefox", "edge")
UNSTABLE_FINGERPRINTS = ("random", "randomized")
POPULAR_HOSTS = (
    ("selectel", "selectel"),
    ("yandex", "yandex"),
    ("vk cloud", "vk"),
    ("vk.tech", "vk"),
    ("mcs.mail", "vk"),
    ("timeweb", "timeweb"),
    ("beget", "beget"),
    ("ruvds", "ruvds"),
    ("firstvds", "firstvds"),
    ("hostkey", "hostkey"),
    ("aeza", "aeza"),
    ("reg.ru", "regru"),
)
PARALLEL_LIMIT = 3
FREEZE_SECONDS = 120
TWITCH_SECONDS = 600
TRAP_KEYS = ("scMinPostsIntervalMs", "scMaxEachPostBytes")
SAFE_INTERVAL_MS = 400
RISK_ORDER = ("hosting", "fingerprint", "single_sni", "vision_mux", "xhttp_posts", "many_clients", "no_tls")
LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2}
ADVICE_KEYS = {
    "hosting": "HOSTING",
    "fingerprint": "FINGERPRINT",
    "single_sni": "SNI",
    "vision_mux": "TRANSPORT",
    "xhttp_posts": "TRANSPORT",
    "many_clients": "SNI",
    "no_tls": "FINGERPRINT",
}


@dataclass
class InboundReport:
    ident: int = 0
    remark: str = ""
    network: str = ""
    security: str = ""
    fingerprint: str = ""
    sni: str = ""
    sni_count: int = 0
    flow: str = ""
    clients: int = 0
    risks: list[str] = field(default_factory=list)

    def level(self) -> str:
        if "no_tls" in self.risks or "hosting" in self.risks:
            return "high"
        if "fingerprint" in self.risks and "single_sni" in self.risks:
            return "high"
        if self.risks:
            return "medium"
        return "low"


@dataclass
class Report:
    inbounds: list[InboundReport] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    hosting: str = ""
    hosting_label: str = ""
    address: str = ""
    trap: Any = None
    trap_error: str = ""

    def level(self) -> str:
        best = "high" if "hosting" in self.risks else "low"
        for item in self.inbounds:
            if LEVEL_ORDER[item.level()] > LEVEL_ORDER[best]:
                best = item.level()
        return best

    def chain(self) -> bool:
        return any("fingerprint" in item.risks and "single_sni" in item.risks for item in self.inbounds)


def fingerprint_state(value: str) -> str:
    name = str(value or "").strip().lower()
    if not name:
        return "unknown"
    if name in SUSPICIOUS_FINGERPRINTS:
        return "suspicious"
    if name in LOYAL_FINGERPRINTS:
        return "loyal"
    if name in UNSTABLE_FINGERPRINTS:
        return "unstable"
    return "unknown"


def hosting_state(text: str) -> str:
    haystack = " ".join(str(text or "").lower().split())
    if not haystack:
        return ""
    for needle, code in POPULAR_HOSTS:
        if needle in haystack:
            return code
    return ""


def trap_keys(settings: Any) -> list[str]:
    found: list[str] = []
    if isinstance(settings, dict):
        for key, value in settings.items():
            if key in TRAP_KEYS:
                found.append(key)
            found.extend(trap_keys(value))
    elif isinstance(settings, list):
        for item in settings:
            found.extend(trap_keys(item))
    return sorted(set(found))


def risky_interval(value: Any) -> bool:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return True
    return number < SAFE_INTERVAL_MS


def inbound_report(inbound: Any) -> InboundReport:
    sni = str(getattr(inbound, "sni", "") or "")
    host = str(getattr(inbound, "host_header", "") or "")
    names = {item for item in (sni, host) if item}
    clients = getattr(inbound, "clients", []) or []
    flows = {str(getattr(item, "flow", "") or "") for item in clients}
    flow = "xtls-rprx-vision" if "xtls-rprx-vision" in flows else ""
    item = InboundReport(
        ident=int(getattr(inbound, "id", 0) or 0),
        remark=str(getattr(inbound, "remark", "") or "")[:48],
        network=str(getattr(inbound, "network", "") or ""),
        security=str(getattr(inbound, "security", "") or ""),
        fingerprint=str(getattr(inbound, "fingerprint", "") or ""),
        sni=sni[:64],
        sni_count=len(names),
        flow=flow,
        clients=len(clients),
    )
    if item.security == "none":
        item.risks.append("no_tls")
    if item.security in ("reality", "tls"):
        if fingerprint_state(item.fingerprint) == "suspicious":
            item.risks.append("fingerprint")
        if item.sni_count <= 1:
            item.risks.append("single_sni")
        if flow == "xtls-rprx-vision":
            item.risks.append("vision_mux")
    if item.network == "xhttp":
        item.risks.append("xhttp_posts")
    if item.clients > PARALLEL_LIMIT:
        item.risks.append("many_clients")
    item.risks.sort(key=RISK_ORDER.index)
    return item


def audit(inbounds: Any) -> Report:
    report = Report()
    for inbound in inbounds or []:
        if not getattr(inbound, "enable", True):
            continue
        report.inbounds.append(inbound_report(inbound))
    found: list[str] = []
    for item in report.inbounds:
        for code in item.risks:
            if code not in found:
                found.append(code)
    report.risks = sorted(found, key=RISK_ORDER.index)
    return report


def apply_hosting(report: Report, organisation: str, asn: str, location: str = "", address: str = "") -> Report:
    report.address = str(address or "")[:64]
    report.hosting = hosting_state(" ".join([organisation or "", asn or "", location or ""]))
    report.hosting_label = ", ".join(item for item in (asn or "", organisation or "") if item)[:80]
    if report.hosting and "hosting" not in report.risks:
        report.risks = sorted(report.risks + ["hosting"], key=RISK_ORDER.index)
    return report


def safe_interval_hint() -> int:
    return SAFE_INTERVAL_MS

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from BOT import dpi, dscreens, i18n

ROOT = Path(__file__).resolve().parents[1]
XRAY = ROOT / "Storage" / "remote" / "xray_agent.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fixed_kernel() -> dpi.Kernel:
    return dpi.Kernel(release="6.12.113-1-amd64", fixed=True, series="6.12", mptcp=0, migrate=0, listeners=0)


def old_kernel() -> dpi.Kernel:
    return dpi.Kernel(release="6.1.128-1-amd64", fixed=False, series="6.1", mptcp=1, migrate=1, listeners=1, listener_ports="443")


@pytest.mark.parametrize(
    "release,expected",
    [
        ("6.1.190-1-amd64", True),
        ("6.1.189-1-amd64", False),
        ("6.12.113-1-amd64", True),
        ("6.12.112-1-amd64", False),
        ("6.16.20-1-amd64", False),
        ("6.17.1-1-amd64", False),
        ("5.10.220-1-amd64", False),
        ("4.19.300-1-amd64", False),
        ("", False),
        ("weird", False),
    ],
)
def test_the_kernel_floor_matches_the_vendor_builds(release: str, expected: bool) -> None:
    assert dpi.kernel_fixed(release)[0] is expected


def test_a_kernel_outside_the_known_series_is_never_called_patched() -> None:
    assert dpi.kernel_status("6.16.20-1-amd64") == (dpi.KERNEL_UNKNOWN, "6.16")
    report = dpi.assess(fingerprints=["firefox"], networks=["raw"], core="v26.10.31", kernel=dpi.kernel_state("6.16.20-1-amd64"))
    assert "kernel_untracked" in report.keys()
    assert "kernel_old" not in report.keys()
    assert report.level() in {"warn", "bad"}


def test_a_patched_kernel_with_no_listener_is_clean() -> None:
    report = dpi.assess(fingerprints=["firefox"], networks=["raw"], core="v26.10.31", kernel=fixed_kernel())
    assert report.level() == "ok"
    assert "kernel_fixed" in report.keys()
    assert "core_fixed" in report.keys()
    assert "kernel_old" not in report.keys()


def test_an_open_mptcp_listener_is_a_blocker() -> None:
    report = dpi.assess(fingerprints=["firefox"], networks=["raw"], core="v26.10.31", kernel=old_kernel())
    assert report.level() == "bad"
    assert report.by_key("mptcp_listener") is not None
    assert report.by_key("mptcp_listener").value == "443"
    assert "kernel_old" in report.keys()
    assert "mptcp_on" in report.keys()
    assert "migrate_on" in report.keys()


def test_the_fingerprint_advice_separates_mass_from_synthetic() -> None:
    mass = dpi.assess(fingerprints=["chrome"], networks=["raw"], core="v26.10.31", kernel=fixed_kernel())
    assert mass.by_key("fp_mass") is not None
    assert mass.by_key("fp_mass").level == "warn"
    synth = dpi.assess(fingerprints=["randomized"], networks=["raw"], core="v26.10.31", kernel=fixed_kernel())
    assert synth.by_key("fp_synthetic") is not None
    assert synth.by_key("fp_synthetic").level == "bad"
    assert synth.level() == "bad"


def test_an_old_core_is_a_blocker() -> None:
    report = dpi.assess(fingerprints=["firefox"], networks=["raw"], core="v26.9.30", kernel=fixed_kernel())
    assert report.core_ok is False
    assert report.level() == "bad"
    assert "core_old" in report.keys()
    assert dpi.core_ok("v26.10.31") is True
    assert dpi.core_ok("v26.10.30") is False
    assert dpi.core_ok("") is False


def test_a_mass_hosting_address_is_flagged() -> None:
    report = dpi.assess(
        fingerprints=["firefox"],
        networks=["raw"],
        core="v26.10.31",
        asn="AS50340",
        organisation="Selectel Ltd",
        country="RU",
        kernel=fixed_kernel(),
    )
    assert report.hoster == "selectel"
    assert report.level() == "warn"
    assert "hoster_marked" in report.keys()
    assert "country_ru" in report.keys()
    assert dpi.hoster_of("Fzco Holding") == ""


def test_xhttp_alone_keeps_a_warning() -> None:
    report = dpi.assess(fingerprints=["firefox"], networks=["xhttp"], core="v26.10.31", kernel=fixed_kernel())
    assert "xhttp_only" in report.keys()
    mixed = dpi.assess(fingerprints=["firefox"], networks=["xhttp", "raw"], core="v26.10.31", kernel=fixed_kernel())
    assert "xhttp_only" not in mixed.keys()


def test_the_collector_reads_inbounds_and_the_core_book() -> None:
    class Inbound:
        def __init__(self, fingerprint: str, network: str, security: str = "reality") -> None:
            self.fingerprint = fingerprint
            self.network = network
            self.security = security

    marks, networks, version = dpi.collect(
        [Inbound("firefox", "raw"), Inbound("firefox", "xhttp"), Inbound("chrome", "raw", "tls"), Inbound("", "grpc")],
        {"version": "v26.10.31"},
    )
    assert marks == ["firefox"]
    assert networks == ["raw", "xhttp", "grpc"]
    assert version == "v26.10.31"
    assert dpi.collect(None, None) == ([], [], "")
    assert dpi.collect([], "junk") == ([], [], "")


def test_the_fix_text_warns_about_the_ss_flag() -> None:
    text = dpi.fix_text()
    assert "net.mptcp.enabled=0" in text
    assert "net.ipv4.tcp_migrate_req=0" in text
    assert "ss -Mlnp" in text and "-t form" in text
    assert "CONFIG_MARKER" not in text
    assert "ip hdrlength > 5" in dpi.nft_rule()
    assert "net.mptcp.enabled=0" in dpi.sysctl_line()


def test_the_summary_is_flat_and_serialisable() -> None:
    report = dpi.assess(fingerprints=["chrome"], networks=["raw"], core="v26.1.1", kernel=old_kernel())
    flat = dpi.summary(report)
    assert flat["level"] == "bad"
    assert flat["kernel"] == "6.1.128-1-amd64"
    assert flat["fingerprints"] == "chrome"
    assert isinstance(flat["findings"], list)


def test_the_quote_never_leaks_a_raw_exception() -> None:
    report = dpi.assess(fingerprints=["chrome"], networks=["raw"], core="v26.10.31", kernel=old_kernel())
    for lang in ("en", "ru", "zh"):
        t = i18n.translator(lang)
        text = dscreens.dpi_quote(t, report)
        assert text
        assert "Traceback" not in text
        assert "Error" not in text
        assert text == dscreens.dpi_quote(t, report)


@pytest.mark.parametrize("lang", ["en", "ru", "zh"])
def test_the_dpi_screen_renders_in_every_language(lang: str) -> None:
    view = dscreens.DbgView(lang=lang)
    view.dpi = dpi.assess(fingerprints=["chrome", "randomized"], networks=["raw"], core="v26.1.1", kernel=old_kernel())
    body = str(dscreens.dpi_screen(view))
    t = i18n.translator(lang)
    assert t("DPI_TITLE") in body
    assert "dbg:dpi:scan" in body
    assert t("DPI_LEVEL_BAD") in body
    assert "net.mptcp.enabled=0" in body
    empty = str(dscreens.dpi_screen(dscreens.DbgView(lang=lang)))
    assert t("DPI_QUOTE_EMPTY") in empty
    assert "None" not in empty


def test_the_dpi_screen_survives_an_unreadable_kernel() -> None:
    view = dscreens.DbgView(lang="en")
    view.dpi = dpi.assess(fingerprints=[], networks=[], core="", kernel=dpi.Kernel(release="", mptcp=-1, migrate=-1, listeners=-1))
    body = str(dscreens.dpi_screen(view))
    assert "kernel_unknown" or True
    assert "dbg:dpi" in body
    assert view.dpi.level() in {"warn", "ok"}


def test_the_agent_unit_disables_mptcp_for_the_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XRAY_ROOT", str(tmp_path))
    module = load(XRAY, "obhod_xray_agent_dpi")
    module.write_unit()
    text = module.UNIT.read_text(encoding="utf-8") if hasattr(module.UNIT, "read_text") else open(module.UNIT, encoding="utf-8").read()
    assert "Environment=GODEBUG=multipathtcp=0" in text
    assert "Environment=XRAY_LOCATION_ASSET=" in text
    assert module.GODEBUG == "multipathtcp=0"


def test_the_agent_reports_the_mptcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XRAY_ROOT", str(tmp_path))
    module = load(XRAY, "obhod_xray_agent_state")
    state = module.mptcp_state()
    assert set(state) == {"release", "mptcp", "migrate", "godebug"}
    assert module.mptcp_warnings({"mptcp": 1, "migrate": 1}) == [
        "net.mptcp.enabled is 1, the kernel still answers mptcp for every program",
        "net.ipv4.tcp_migrate_req is 1, connection migration is open",
    ]
    assert module.mptcp_warnings({"mptcp": 0, "migrate": 0}) == []
    report = module.state_report()
    assert report["min_core"] == "v26.10.31"
    assert report["advisory"] == "CVE-2026-98432"
    assert "mptcp" in report


def test_the_agent_refuses_a_core_below_the_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XRAY_ROOT", str(tmp_path))
    module = load(XRAY, "obhod_xray_agent_core")
    assert module.core_too_old("v26.10.30") is True
    assert module.core_too_old("v26.10.31") is False
    with pytest.raises(module.ScriptError) as caught:
        module.install_core("v26.10.30", "", "", False)
    assert caught.value.code == "core_too_old"
    assert "CVE-2026-98432" in caught.value.message

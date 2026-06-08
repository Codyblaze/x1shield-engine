from __future__ import annotations

from app.datacenter_ranges import lookup_provider
from app.engine import HeuristicsEngine
from app.network_rules import DatacenterIPRule, IPRotationRule
from app.schemas import AnalyzeRequest, BrowserData, Fingerprint, NetworkData

WALLET = "0x" + "a" * 40
AWS_IP = "52.1.2.3"
RESIDENTIAL_IP = "24.48.0.1"


def test_lookup_provider_identifies_cloud():
    assert lookup_provider(AWS_IP) == "AWS"


def test_lookup_provider_residential_and_invalid():
    assert lookup_provider(RESIDENTIAL_IP) is None
    assert lookup_provider("not-an-ip") is None
    assert lookup_provider(None) is None


def test_datacenter_rule_flags_cloud_ip():
    fp = Fingerprint(network=NetworkData(ip_address=AWS_IP))
    result = DatacenterIPRule().evaluate(fp)

    assert result.tripped is True
    assert result.score == 80.0
    assert "AWS" in (result.detail or "")


def test_datacenter_rule_passes_residential_ip():
    fp = Fingerprint(network=NetworkData(ip_address=RESIDENTIAL_IP))
    result = DatacenterIPRule().evaluate(fp)

    assert result.tripped is False
    assert result.score == 0.0


def test_ip_rotation_flags_many_ips():
    rotating = [f"24.{octet}.0.1" for octet in range(48, 53)]  # 5 distinct /24s
    fp = Fingerprint(network=NetworkData(recent_ips=rotating))
    result = IPRotationRule().evaluate(fp)

    assert result.tripped is True
    assert result.score >= 50.0


def test_ip_rotation_ignores_short_history():
    fp = Fingerprint(network=NetworkData(recent_ips=[RESIDENTIAL_IP]))
    result = IPRotationRule().evaluate(fp)

    assert result.tripped is False


def test_engine_blocks_on_datacenter_ip():
    engine = HeuristicsEngine()
    req = AnalyzeRequest(
        wallet_address=WALLET,
        fingerprint=Fingerprint(network=NetworkData(ip_address=AWS_IP)),
    )
    resp = engine.analyze(req)

    assert resp.is_human is False
    assert "datacenter_ip" in resp.flags


def test_scoring_override_single_critical_signal_blocks():
    # Only the WebGL rule trips; everything else looks human. The critical
    # override must still block instead of averaging the signal away.
    engine = HeuristicsEngine()
    req = AnalyzeRequest(
        wallet_address=WALLET,
        fingerprint=Fingerprint(browser_data=BrowserData(webgl_renderer="SwiftShader")),
    )
    resp = engine.analyze(req)

    assert resp.is_human is False
    assert resp.risk_score >= 70
    assert "webgl_hardware_spoofing" in resp.flags

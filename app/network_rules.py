from __future__ import annotations

import ipaddress

from app.datacenter_ranges import lookup_provider
from app.rules import HeuristicRule
from app.schemas import Fingerprint, RuleResult


class DatacenterIPRule(HeuristicRule):
    name = "datacenter_ip"
    weight = 1.5

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        result = RuleResult(name=self.name, tripped=False, score=0.0, detail=None)

        network = fingerprint.network
        if not network or not network.ip_address:
            return result

        provider = lookup_provider(network.ip_address)
        if provider:
            result.tripped = True
            result.score = 80.0
            result.detail = (
                f"Connection originates from datacenter/cloud provider ({provider}). "
                "Residential users rarely transact from cloud IPs."
            )

        return result


class IPRotationRule(HeuristicRule):
    name = "ip_rotation"
    weight = 1.2

    MIN_IPS_TO_EVALUATE = 3
    ROTATION_THRESHOLD = 5

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        result = RuleResult(name=self.name, tripped=False, score=0.0, detail=None)

        network = fingerprint.network
        if not network or not network.recent_ips:
            return result

        unique = set()
        subnets = set()
        for raw in network.recent_ips:
            try:
                addr = ipaddress.ip_address(raw.strip())
            except (ValueError, AttributeError):
                continue
            unique.add(str(addr))
            if addr.version == 4:
                subnets.add(str(ipaddress.ip_network(f"{addr}/24", strict=False)))

        if len(unique) < self.MIN_IPS_TO_EVALUATE:
            result.detail = "insufficient IP history to assess rotation"
            return result

        providers = {lookup_provider(ip) for ip in unique}
        providers.discard(None)

        score = 0.0
        if len(unique) >= self.ROTATION_THRESHOLD:
            score += 60.0
        else:
            score += 35.0
        # Hopping across multiple datacenter providers is a hallmark of proxy farms.
        if len(providers) >= 2:
            score += 30.0
        elif len(providers) == 1:
            score += 15.0
        if len(subnets) >= self.ROTATION_THRESHOLD:
            score += 15.0

        score = min(score, 100.0)
        result.score = score
        result.tripped = score >= 50.0
        result.detail = (
            f"unique_ips={len(unique)} subnets={len(subnets)} "
            f"datacenter_providers={len(providers)}"
        )

        return result

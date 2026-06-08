"""Static datacenter/cloud CIDR intelligence.

Sybil farms almost always run out of cloud datacenters rather than residential
ISPs. This module ships a curated seed of well-known provider ranges so the
engine can flag datacenter origins offline, with no API key or paid lookup.

The list is intentionally a representative seed, not exhaustive. Each provider
publishes its full, authoritative ranges for free (e.g. AWS ip-ranges.json,
GCP cloud.json, Azure ServiceTags) and a future job can refresh from those.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

PROVIDER_RANGES: dict[str, list[str]] = {
    "AWS": [
        "3.0.0.0/9",
        "13.32.0.0/15",
        "15.177.0.0/18",
        "18.32.0.0/11",
        "52.0.0.0/11",
        "54.224.0.0/12",
        "99.77.128.0/17",
    ],
    "GCP": [
        "34.0.0.0/10",
        "35.184.0.0/13",
        "35.192.0.0/14",
        "104.196.0.0/14",
        "130.211.0.0/16",
    ],
    "Azure": [
        "20.33.0.0/16",
        "20.34.0.0/15",
        "40.64.0.0/10",
        "52.224.0.0/11",
        "104.40.0.0/13",
    ],
    "DigitalOcean": [
        "104.131.0.0/16",
        "159.65.0.0/16",
        "159.89.0.0/16",
        "165.227.0.0/16",
        "167.71.0.0/16",
        "167.99.0.0/16",
        "178.62.0.0/16",
    ],
    "OVH": [
        "51.68.0.0/16",
        "51.75.0.0/16",
        "51.83.0.0/16",
        "51.91.0.0/16",
        "145.239.0.0/16",
        "151.80.0.0/16",
    ],
    "Hetzner": [
        "5.9.0.0/16",
        "78.46.0.0/15",
        "88.198.0.0/16",
        "116.202.0.0/15",
        "168.119.0.0/16",
    ],
    "Linode": [
        "45.33.0.0/17",
        "45.79.0.0/16",
        "139.162.0.0/16",
        "172.104.0.0/15",
        "173.255.192.0/18",
    ],
}


def _compile() -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    compiled: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    for provider, cidrs in PROVIDER_RANGES.items():
        for cidr in cidrs:
            compiled.append((ipaddress.ip_network(cidr), provider))
    return compiled


_NETWORKS = _compile()


@lru_cache(maxsize=4096)
def lookup_provider(ip: str | None) -> str | None:
    """Return the datacenter provider for an IP, or None if residential/invalid."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for network, provider in _NETWORKS:
        if addr in network:
            return provider
    return None

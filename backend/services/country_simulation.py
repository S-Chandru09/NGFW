"""Simulated country-to-IP mapping for firewall geo evaluation."""

from ipaddress import ip_address, ip_network
from typing import Optional

COUNTRY_SIMULATION_DATA: dict[str, dict] = {
  "US": {
    "name": "United States",
    "sample_ip": "8.8.8.8",
    "networks": ["8.8.8.0/24", "192.0.2.0/24", "198.51.100.0/24"],
  },
  "IN": {
    "name": "India",
    "sample_ip": "49.36.1.10",
    "networks": ["49.36.0.0/16", "103.21.244.0/24", "117.192.0.0/16"],
  },
  "CN": {
    "name": "China",
    "sample_ip": "14.215.177.39",
    "networks": ["14.215.0.0/16", "59.24.0.0/16", "1.0.1.0/24"],
  },
  "RU": {
    "name": "Russia",
    "sample_ip": "95.108.213.141",
    "networks": ["95.108.0.0/16", "87.250.0.0/16"],
  },
  "DE": {
    "name": "Germany",
    "sample_ip": "217.160.0.1",
    "networks": ["217.160.0.0/16", "5.9.0.0/16"],
  },
  "GB": {
    "name": "United Kingdom",
    "sample_ip": "81.2.69.142",
    "networks": ["81.2.0.0/16", "194.74.0.0/16"],
  },
  "BR": {
    "name": "Brazil",
    "sample_ip": "177.54.144.1",
    "networks": ["177.54.0.0/16", "191.36.0.0/16"],
  },
  "JP": {
    "name": "Japan",
    "sample_ip": "210.152.0.1",
    "networks": ["210.152.0.0/16", "126.0.0.0/16"],
  },
  "AU": {
    "name": "Australia",
    "sample_ip": "1.1.1.1",
    "networks": ["1.1.1.0/24", "203.0.113.0/24"],
  },
  "FR": {
    "name": "France",
    "sample_ip": "80.12.0.1",
    "networks": ["80.12.0.0/16", "90.0.0.0/16"],
  },
}

_NETWORK_LOOKUP: list[tuple] = []


def _build_network_lookup() -> list[tuple]:
  if _NETWORK_LOOKUP:
    return _NETWORK_LOOKUP

  for country_code, country_data in COUNTRY_SIMULATION_DATA.items():
    for network_cidr in country_data["networks"]:
      _NETWORK_LOOKUP.append((ip_network(network_cidr), country_code))

  return _NETWORK_LOOKUP


def list_supported_countries() -> list[dict[str, str]]:
  return [
    {
      "country_code": code,
      "country_name": data["name"],
      "sample_ip": data["sample_ip"],
    }
    for code, data in sorted(COUNTRY_SIMULATION_DATA.items())
  ]


def resolve_country_from_ip(ip_value: str) -> Optional[str]:
  try:
    address = ip_address(ip_value)
  except ValueError:
    return None

  for network, country_code in _build_network_lookup():
    if address in network:
      return country_code

  return None


def get_sample_ip_for_country(country_code: str) -> Optional[str]:
  country_data = COUNTRY_SIMULATION_DATA.get(country_code.upper())
  if country_data is None:
    return None
  return country_data["sample_ip"]


def get_country_name(country_code: str) -> Optional[str]:
  country_data = COUNTRY_SIMULATION_DATA.get(country_code.upper())
  if country_data is None:
    return None
  return country_data["name"]

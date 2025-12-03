from __future__ import annotations

import requests

from domain.entity import HostReport, ServiceInfo, VulnerabilityDetail
from domain.repository import ShodanRepository

API_BASE_URL = "https://api.shodan.io"


def normalize_references(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def build_vuln_detail(identifier: str, data) -> VulnerabilityDetail:
    if isinstance(data, dict):
        return VulnerabilityDetail(
            cve=identifier,
            cvss=data.get("cvss"),
            verified=data.get("verified"),
            references=normalize_references(
                data.get("references") or data.get("ref") or data.get("urls")
            ),
        )
    return VulnerabilityDetail(identifier)


def extract_vulns(raw) -> list[VulnerabilityDetail]:
    findings: list[VulnerabilityDetail] = []
    if not raw:
        return findings
    if isinstance(raw, dict):
        for identifier, data in raw.items():
            findings.append(build_vuln_detail(str(identifier), data))
        return findings
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, str):
                findings.append(VulnerabilityDetail(entry))
            elif isinstance(entry, dict):
                identifier = str(entry.get("cve") or entry.get("id") or "VULN")
                findings.append(build_vuln_detail(identifier, entry))
            else:
                findings.append(VulnerabilityDetail(str(entry)))
        return findings
    return [VulnerabilityDetail(str(raw))]


class ShodanAPIRepository(ShodanRepository):
    """
    Implementação que consulta a API oficial do Shodan.
    """

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def shodan_request(self, path: str, timeout: int):
        url = f"{API_BASE_URL}{path}"
        params = {"key": self.api_key}
        response = requests.get(url, params=params, timeout=timeout)
        if response.status_code == 404:
            raise ValueError("Alvo não encontrado no Shodan")
        response.raise_for_status()
        return response.json()

    def fetch_domain_history(self, domain: str, timeout: int) -> tuple[list[str], str | None]:
        url = f"{API_BASE_URL}/dns/domain/{domain}"
        params = {"key": self.api_key, "history": "true"}
        try:
            response = requests.get(url, params=params, timeout=timeout)
        except requests.RequestException as exc:
            return [], f"falha de rede: {exc}"

        if response.status_code == 404:
            # Sem dados históricos para o domínio: não é um erro
            return [], None

        if not response.ok:
            return [], f"HTTP {response.status_code}"

        try:
            payload = response.json()
        except ValueError as exc:
            return [], f"resposta inválida do Shodan: {exc}"

        ips: list[str] = []
        for record in payload.get("data", []):
            record_type = (record.get("type") or "").upper()
            value = record.get("value")
            if record_type != "A" or not value:
                continue
            ips.append(str(value))
        return ips, None

    def fetch_host_report(self, ip: str, timeout: int) -> HostReport:
        payload = self.shodan_request(f"/shodan/host/{ip}", timeout)
        services: list[ServiceInfo] = []
        for entry in payload.get("data", []):
            service = ServiceInfo(
                port=entry.get("port"),
                transport=(entry.get("transport") or "").upper(),
                product=entry.get("product"),
                version=entry.get("version"),
                cpe=entry.get("cpe", []) or [],
                tags=entry.get("tags", []) or [],
                vulns=extract_vulns(entry.get("vulns")),
                info=(entry.get("info") or entry.get("_shodan", {}).get("module")),
            )
            services.append(service)

        location_parts = [
            payload.get("city"),
            payload.get("region_code"),
            payload.get("country_name"),
        ]
        location = ", ".join(part for part in location_parts if part)

        host_report = HostReport(
            ip=payload.get("ip_str", ip),
            hostnames=payload.get("hostnames", []) or [],
            org=payload.get("org"),
            isp=payload.get("isp"),
            os=payload.get("os"),
            location=location or None,
            open_ports=sorted(payload.get("ports", [])),
            tags=payload.get("tags", []) or [],
            vulns=extract_vulns(payload.get("vulns")),
            services=services,
        )

        return host_report

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests

from domain.entity import HostReport, ServiceInfo, VulnerabilityDetail
from domain.errors import (
    ShodanHTTPError,
    ShodanNetworkError,
    ShodanNotFoundError,
    ShodanRateLimitError,
    ShodanTimeoutError,
)
from domain.repository import ShodanRepository

API_BASE_URL = "https://api.shodan.io"
HISTORY_YEARS = 3
RECENT_HOURS = 24
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


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


def parse_month(value) -> str | None:
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        elif isinstance(value, str):
            # Normaliza timestamps do Shodan, ex: 2025-01-02T12:00:00.000000
            clean = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        else:
            return None
        return dt.strftime("%Y-%m")
    except Exception:
        return None


def parse_timestamp(value) -> datetime | None:
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str):
            clean = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None
    return None


def cvss_score(value: float | str | None) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def within_history_window(timestamp: datetime, cutoff: datetime) -> bool:
    return timestamp >= cutoff


def build_recent_vulns(entries: list[dict], cutoff: datetime) -> list[VulnerabilityDetail]:
    recent: dict[str, VulnerabilityDetail] = {}
    for entry in entries or []:
        timestamp = parse_timestamp(entry.get("timestamp"))
        if not timestamp or timestamp < cutoff:
            continue
        for vuln in extract_vulns(entry.get("vulns")):
            recent.setdefault(vuln.cve, vuln)
    return list(recent.values())


def build_history_trend(entries: list[dict]) -> dict[str, list[int]] | None:
    monthly_ports: dict[str, set[int]] = {}
    monthly_cves: dict[str, int] = {}
    cutoff = datetime.now(timezone.utc) - timedelta(days=365 * HISTORY_YEARS)

    for entry in entries or []:
        timestamp = parse_timestamp(entry.get("timestamp"))
        if not timestamp or not within_history_window(timestamp, cutoff):
            continue
        month = timestamp.strftime("%Y-%m")
        monthly_ports.setdefault(month, set())
        monthly_cves.setdefault(month, 0)
        port = entry.get("port")
        if port:
            monthly_ports[month].add(port)
        for _ in extract_vulns(entry.get("vulns")):
            monthly_cves[month] += 1

    all_months = sorted(set(monthly_ports.keys()) | set(monthly_cves.keys()))
    if not all_months:
        return None
    labels = all_months
    ports = [len(monthly_ports.get(month, set())) for month in labels]
    cves = [monthly_cves.get(month, 0) for month in labels]
    return {"labels": labels, "ports": ports, "cves": cves}


def build_history_detail(entries: list[dict]) -> list[dict[str, object]] | None:
    """
    Retorna uma lista ordenada por mês com portas e CVEs observados naquele snapshot.
    """
    buckets: dict[str, dict[str, object]] = {}
    cutoff = datetime.now(timezone.utc) - timedelta(days=365 * HISTORY_YEARS)
    for entry in entries or []:
        timestamp = parse_timestamp(entry.get("timestamp"))
        if not timestamp or not within_history_window(timestamp, cutoff):
            continue
        month = timestamp.strftime("%Y-%m")
        bucket = buckets.setdefault(
            month,
            {
                "period": month,
                "ports": set(),
                "cves": set(),
                "severity": {level: 0 for level in SEVERITY_ORDER},
            },
        )
        port = entry.get("port")
        if port:
            bucket["ports"].add(port)
        for vuln in extract_vulns(entry.get("vulns")):
            bucket["cves"].add(vuln.cve)
            severity = severity_from_cvss(cvss_score(vuln.cvss))
            bucket["severity"][severity] = bucket["severity"].get(severity, 0) + 1
    if not buckets:
        return None
    ordered = []
    for period in sorted(buckets.keys(), reverse=True):
        data = buckets[period]
        ordered.append(
            {
                "period": period,
                "ports": sorted(data["ports"]),
                "cves": sorted(data["cves"]),
                "severity": data.get("severity", {}),
            }
        )
    return ordered


def select_latest_services(entries: list[dict]) -> list[dict]:
    """
    Quando history=true, o Shodan devolve snapshots antigos em payload['data'].
    Seleciona o snapshot mais recente por (porta, transporte) para evitar cartões duplicados.
    """
    latest: dict[tuple[int | None, str], tuple[dict, datetime | None]] = {}
    for entry in entries:
        port = entry.get("port")
        transport = (entry.get("transport") or "").upper()
        key = (port, transport)
        current_ts = parse_timestamp(entry.get("timestamp"))
        if key not in latest:
            latest[key] = (entry, current_ts)
            continue
        _, stored_ts = latest[key]
        if current_ts and (stored_ts is None or current_ts > stored_ts):
            latest[key] = (entry, current_ts)
    # Ordena por porta para manter consistência visual
    sorted_items = sorted(latest.values(), key=lambda item: (item[0].get("port") or 0))
    return [item[0] for item in sorted_items]


class ShodanAPIRepository(ShodanRepository):
    """
    Implementação que consulta a API oficial do Shodan.
    """

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def shodan_request(self, path: str, timeout: int, params: dict | None = None):
        url = f"{API_BASE_URL}{path}"
        merged_params = {"key": self.api_key}
        if params:
            merged_params.update(params)
        try:
            response = requests.get(url, params=merged_params, timeout=timeout)
        except requests.Timeout as exc:
            raise ShodanTimeoutError() from exc
        except requests.RequestException as exc:
            raise ShodanNetworkError(str(exc)) from exc
        if response.status_code == 404:
            raise ShodanNotFoundError("Alvo não encontrado no Shodan")
        if response.status_code == 429:
            raise ShodanRateLimitError(status_code=429)
        if not response.ok:
            raise ShodanHTTPError(status_code=response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise ShodanHTTPError(message="Resposta inválida do Shodan") from exc

    def fetch_domain_history(self, domain: str, timeout: int) -> tuple[list[str], str | None]:
        url = f"{API_BASE_URL}/dns/domain/{domain}"
        params = {"key": self.api_key, "history": "true"}
        try:
            response = requests.get(url, params=params, timeout=timeout)
        except requests.Timeout as exc:
            return [], f"tempo limite: {exc}"
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

    def fetch_host_report(self, ip: str, timeout: int, include_history: bool = False) -> HostReport:
        params = {"history": "true"} if include_history else None
        payload = self.shodan_request(f"/shodan/host/{ip}", timeout, params=params)
        entries = payload.get("data", []) or []
        service_entries = select_latest_services(entries) if include_history else entries
        services: list[ServiceInfo] = []
        for entry in service_entries:
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

        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENT_HOURS)
        recent_vulns = build_recent_vulns(entries, recent_cutoff)

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
            recent_vulns=recent_vulns,
            history_trend=build_history_trend(payload.get("data", [])) if include_history else None,
            history_detail=build_history_detail(payload.get("data", [])) if include_history else None,
        )

        return host_report

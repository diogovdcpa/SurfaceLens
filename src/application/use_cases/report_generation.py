from __future__ import annotations

import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from typing import List, Tuple

from application.report_models import ReportHost, ReportModel, ReportSummary
from application.report_utils import (
    collect_all_vulns,
    is_ip,
    severity_counts_for_host,
    severity_counts_global,
    severity_counts_for_vulns,
)
from domain.entity import HostReport, ReportWarning
from domain.errors import (
    ShodanHTTPError,
    ShodanNetworkError,
    ShodanNotFoundError,
    ShodanRateLimitError,
    ShodanTimeoutError,
)
from domain.repository import ShodanRepository

DEFAULT_TIMEOUT = 60
MAX_TARGET_IPS = 1024
PAUSE_BETWEEN_REQUESTS = 1.0
TARGET_SPLIT_PATTERN = re.compile(r",")


def load_api_key(user_value: str | None, fallback_env: str | None = None) -> str:
    api_key = user_value or fallback_env
    if not api_key:
        raise RuntimeError("Informe a chave do Shodan ou configure SHODAN_API_KEY")
    return api_key


def normalize_targets(raw: str | None) -> List[str]:
    """
    Divide uma string com alvos separados por vírgula em uma lista normalizada.
    Remove espaços extras e ignora entradas vazias.
    """
    if not raw:
        raise ValueError("Informe ao menos um IP, hostname, domínio ou bloco CIDR.")
    tokens = [segment.strip() for segment in TARGET_SPLIT_PATTERN.split(raw)]
    targets = [token for token in tokens if token]
    if not targets:
        raise ValueError("Informe ao menos um IP, hostname, domínio ou bloco CIDR.")
    return targets


def resolve_dns_locally(target: str) -> tuple[List[str], str | None]:
    try:
        addrinfo = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        return [], str(exc)

    unique_ips: List[str] = []
    for family, _, _, _, sockaddr in addrinfo:
        if family == socket.AF_INET:
            ip = sockaddr[0]
        elif family == socket.AF_INET6:
            ip = sockaddr[0]
        else:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in unique_ips:
            unique_ips.append(ip)

    if not unique_ips:
        return [], "nenhum registro A/AAAA encontrado"
    return unique_ips, None


def dedupe_ips(values: List[str]) -> List[str]:
    unique: List[str] = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        unique.append(value)
        seen.add(value)
    return unique


def limit_target_ips(target: str, ips: List[str]) -> tuple[List[str], ReportWarning | None]:
    if len(ips) <= MAX_TARGET_IPS:
        return ips, None
    return ips[:MAX_TARGET_IPS], ReportWarning(ip=target, kind="max_ips")


def resolve_domain_target(
    target: str,
    repository: ShodanRepository,
    timeout: int,
) -> tuple[List[str], List[ReportWarning]]:
    warnings: List[ReportWarning] = []
    dns_ips, dns_error = resolve_dns_locally(target)
    if dns_error or not dns_ips:
        warnings.append(ReportWarning(ip=target, kind="dns_local_failed", detail=dns_error))
        fallback_ips, fallback_error = repository.fetch_dns_resolve(target, timeout)
        if fallback_error:
            warnings.append(ReportWarning(ip=target, kind="dns_shodan_failed", detail=fallback_error))
        elif fallback_ips:
            dns_ips = fallback_ips

    shodan_ips, error = repository.fetch_domain_history(target, timeout)
    if error:
        warnings.append(ReportWarning(ip=target, kind="domain_lookup", detail=error))

    combined = dedupe_ips([*dns_ips, *shodan_ips])
    if not combined:
        search_ips, search_error = repository.fetch_host_search(target, timeout)
        if search_error:
            warnings.append(
                ReportWarning(ip=target, kind="host_search_failed", detail=search_error)
            )
        else:
            combined = search_ips
    if not combined:
        raise RuntimeError(
            f"Nenhum IP encontrado para {target} após resolver DNS local e Shodan."
        )

    combined, limit_warning = limit_target_ips(target, combined)
    if limit_warning:
        warnings.append(limit_warning)
    return combined, warnings


def resolve_target(
    target: str,
    repository: ShodanRepository,
    timeout: int,
) -> tuple[List[str], List[ReportWarning]]:
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            # Not a valid CIDR, continue with hostname flow
            pass
        else:
            total_addresses = int(network.num_addresses)
            if total_addresses > MAX_TARGET_IPS:
                raise RuntimeError(
                    f"O bloco {target} possui {total_addresses} endereços, acima do limite de {MAX_TARGET_IPS}."
                )
            return [str(ip) for ip in network], []

    if is_ip(target):
        return [target], []

    return resolve_domain_target(target, repository, timeout)


def collect_host_reports(
    target: str,
    repository: ShodanRepository,
    timeout: int = DEFAULT_TIMEOUT,
    include_history: bool = False,
    pause: float = PAUSE_BETWEEN_REQUESTS,
) -> Tuple[List[HostReport], List[ReportWarning]]:
    ips, domain_warnings = resolve_target(target, repository, timeout)
    host_reports: List[HostReport] = []
    warnings: List[ReportWarning] = domain_warnings
    for idx, ip in enumerate(ips, start=1):
        try:
            host_reports.append(repository.fetch_host_report(ip, timeout, include_history=include_history))
        except ShodanNotFoundError as not_found:
            warnings.append(ReportWarning(ip=ip, kind="not_found", detail=str(not_found)))
        except ShodanTimeoutError:
            warnings.append(ReportWarning(ip=ip, kind="timeout"))
        except ShodanRateLimitError as rate_err:
            detail = str(rate_err.status_code) if rate_err.status_code else None
            warnings.append(ReportWarning(ip=ip, kind="rate_limit", detail=detail))
            time.sleep(5)
            continue
        except ShodanHTTPError as http_err:
            detail = str(http_err.status_code) if http_err.status_code else str(http_err)
            warnings.append(ReportWarning(ip=ip, kind="http", detail=detail))
        except ShodanNetworkError as network_err:
            warnings.append(ReportWarning(ip=ip, kind="network", detail=str(network_err) or None))

        if idx < len(ips) and pause > 0:
            time.sleep(pause)
    if not host_reports and ips:
        lookup_error_kinds = {"timeout", "network", "http", "rate_limit"}
        if not any(warning.kind in lookup_error_kinds for warning in warnings):
            warnings.append(ReportWarning(ip=target, kind="no_shodan_data"))
    return host_reports, warnings


def build_report_model(
    target: str,
    hosts: List[HostReport],
    company: str | None = None,
) -> ReportModel:
    normalized_company = (company or "SurfaceLens").strip() or "SurfaceLens"
    generated_at = datetime.now(timezone.utc)

    host_models: List[ReportHost] = []
    for host in hosts:
        all_vulns = collect_all_vulns(host)
        recent_vulns = host.recent_vulns or []
        recent_severity = severity_counts_for_vulns(recent_vulns)
        host_models.append(
            ReportHost(
                host=host,
                all_vulns=all_vulns,
                severity_counts=severity_counts_for_host(host),
                unique_ports=len(set(host.open_ports)),
                recent_vulns=recent_vulns,
                recent_severity_counts=recent_severity,
            )
        )

    severity_24h: dict[str, int] = {}
    for host_item in host_models:
        for key, value in host_item.recent_severity_counts.items():
            severity_24h[key] = severity_24h.get(key, 0) + value

    summary = ReportSummary(
        total_hosts=len(host_models),
        total_ports=sum(item.unique_ports for item in host_models),
        total_vulns=sum(len(item.all_vulns) for item in host_models),
        severity_global=severity_counts_global(hosts),
        total_vulns_24h=sum(len(item.recent_vulns) for item in host_models),
        severity_24h=severity_24h,
        history_enabled=any(item.host.history_detail for item in host_models),
    )

    return ReportModel(
        target=target,
        company=normalized_company,
        generated_at=generated_at,
        hosts=host_models,
        summary=summary,
    )

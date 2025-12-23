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


def resolve_target(target: str) -> List[str]:
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            # Not a valid CIDR, continue with hostname flow
            pass
        else:
            addresses = [str(ip) for ip in network]
            if len(addresses) > MAX_TARGET_IPS:
                raise RuntimeError(
                    f"O bloco {target} possui {len(addresses)} endereços, acima do limite de {MAX_TARGET_IPS}."
                )
            return addresses

    if is_ip(target):
        return [target]
    hostname, _, addresses = socket.gethostbyname_ex(target)
    unique_ips = []
    for ip in addresses:
        if ip not in unique_ips:
            unique_ips.append(ip)
    if not unique_ips:
        raise RuntimeError(f"Nenhum IP encontrado para {target} (host {hostname})")
    return unique_ips


def expand_ips_with_shodan_domain_data(
    target: str,
    dns_ips: List[str],
    repository: ShodanRepository,
    timeout: int,
) -> tuple[List[str], List[ReportWarning]]:
    """
    Combina os IPs resolvidos via DNS com os IPs históricos vistos pelo Shodan
    para o domínio informado.
    """
    if is_ip(target) or "/" in target:
        return dns_ips, []

    shodan_ips, error = repository.fetch_domain_history(target, timeout)
    warnings: List[ReportWarning] = []
    if error:
        warnings.append(ReportWarning(ip=target, kind="domain_lookup", detail=error))
        return dns_ips, warnings

    if not shodan_ips:
        return dns_ips, warnings

    combined: List[str] = []
    seen = set()
    for value in [*dns_ips, *shodan_ips]:
        if value in seen:
            continue
        combined.append(value)
        seen.add(value)

    if len(combined) > MAX_TARGET_IPS:
        raise RuntimeError(
            (
                f"O domínio {target} possui {len(combined)} IPs combinando DNS e Shodan, "
                f"acima do limite de {MAX_TARGET_IPS}. Reduza o escopo antes de continuar."
            )
        )
    return combined, warnings


def collect_host_reports(
    target: str,
    repository: ShodanRepository,
    timeout: int = DEFAULT_TIMEOUT,
    include_history: bool = False,
    pause: float = PAUSE_BETWEEN_REQUESTS,
) -> Tuple[List[HostReport], List[ReportWarning]]:
    ips = resolve_target(target)
    ips, domain_warnings = expand_ips_with_shodan_domain_data(target, ips, repository, timeout)
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

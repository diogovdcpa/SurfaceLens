from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Sequence

from domain.entity import HostReport, ReportWarning, VulnerabilityDetail

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def is_ip(value: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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


def format_vuln_summary(vuln: VulnerabilityDetail) -> str:
    score = cvss_score(vuln.cvss)
    parts: List[str] = [vuln.cve]
    meta: List[str] = []
    if score:
        meta.append(f"CVSS {score:.1f}")
    if vuln.verified is True:
        meta.append("verificado")
    elif vuln.verified is False:
        meta.append("não verificado")
    if meta:
        parts.append(f"({' | '.join(meta)})")
    if vuln.references:
        refs = ", ".join(vuln.references[:2])
        parts.append(f"Refs: {refs}")
    return " ".join(parts)


def sort_vulnerabilities(vulns: List[VulnerabilityDetail]) -> List[VulnerabilityDetail]:
    return sorted(vulns, key=lambda v: cvss_score(v.cvss), reverse=True)


def extract_year_from_cve(vuln: VulnerabilityDetail) -> str:
    match = re.search(r"(\\d{4})", vuln.cve)
    if match:
        return match.group(1)
    return "Sem ano"


def group_vulns_by_year_and_severity(
    vulns: List[VulnerabilityDetail],
) -> List[tuple[str, Dict[str, List[VulnerabilityDetail]]]]:
    groups: Dict[str, Dict[str, List[VulnerabilityDetail]]] = {}
    for vuln in vulns:
        year = extract_year_from_cve(vuln)
        score = cvss_score(vuln.cvss)
        severity = severity_from_cvss(score)
        groups.setdefault(year, {}).setdefault(severity, []).append(vuln)

    ordered_years = sorted(
        groups.keys(),
        reverse=True,
        key=lambda y: (1, y) if y.isdigit() else (0, y),
    )
    result = []
    for year in ordered_years:
        severity_map = groups[year]
        ordered_map: Dict[str, List[VulnerabilityDetail]] = {}
        for sev in SEVERITY_ORDER:
            if sev in severity_map:
                ordered_map[sev] = sort_vulnerabilities(severity_map[sev])
        result.append((year, ordered_map))
    return result


def summarize_total_vulns(vulns: List[VulnerabilityDetail]) -> str:
    if not vulns:
        return "0"
    total = len(vulns)
    return f"{total} vulnerabilidade{'s' if total != 1 else ''}"


def collect_all_vulns(host: HostReport) -> List[VulnerabilityDetail]:
    aggregated: Dict[str, VulnerabilityDetail] = {}
    for vuln in host.vulns:
        aggregated[vuln.cve] = vuln
    for service in host.services:
        for vuln in service.vulns:
            aggregated.setdefault(vuln.cve, vuln)
    return list(aggregated.values())


def severity_counts_for_host(host: HostReport) -> Dict[str, int]:
    counts: Dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
    for vuln in host.vulns:
        sev = severity_from_cvss(cvss_score(vuln.cvss))
        counts.setdefault(sev, 0)
        counts[sev] += 1
    for service in host.services:
        for vuln in service.vulns:
            sev = severity_from_cvss(cvss_score(vuln.cvss))
            counts.setdefault(sev, 0)
            counts[sev] += 1
    return counts


def severity_counts_for_vulns(vulns: List[VulnerabilityDetail]) -> Dict[str, int]:
    counts: Dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
    for vuln in vulns:
        sev = severity_from_cvss(cvss_score(vuln.cvss))
        counts.setdefault(sev, 0)
        counts[sev] += 1
    return counts


def severity_counts_global(hosts: List[HostReport]) -> Dict[str, int]:
    counts: Dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
    for host in hosts:
        host_counts = severity_counts_for_host(host)
        for key, value in host_counts.items():
            counts.setdefault(key, 0)
            counts[key] += value
    return counts


def slugify(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe.strip("-_.") or "alvo"


def classify_target_label(targets: Sequence[str]) -> str:
    """
    Define o prefixo do arquivo com base na quantidade e no tipo dos alvos.
    """
    if not targets:
        return "relatorio-alvo"
    if len(targets) == 1:
        target = targets[0]
        if "/" in target:
            network, _, cidr = target.partition("/")
            return f"relatorio-{slugify(network)}-{cidr or 'cidr'}"
        if is_ip(target):
            return f"relatorio-{slugify(target)}"
        return f"relatorio-{slugify(target)}"

    # múltiplos alvos
    all_ips = all(is_ip(item) and "/" not in item for item in targets)
    all_blocks = all("/" in item for item in targets)
    all_domains = all(not is_ip(item.split("/")[0]) and "/" not in item for item in targets)

    if all_ips:
        return "relatorio-ips"
    if all_blocks:
        return "relatorio-blocos"
    if all_domains:
        return "relatorio-dominios"
    return "relatorio-alvos"


def default_output_name(targets: Sequence[str]) -> str:
    """
    Gera o nome final do PDF com base em todos os alvos recebidos.
    """
    prefix = classify_target_label(targets)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{timestamp}.pdf"


def list_to_text(values: Sequence[str]) -> str | None:
    if not values:
        return None
    return ", ".join(values)


def warning_message_text(warning: ReportWarning, verbose: bool = False) -> str:
    base: str
    if warning.kind == "not_found":
        base = f"{warning.ip}: não encontrado no Shodan."
    elif warning.kind == "timeout":
        base = f"{warning.ip}: tempo limite excedido ao consultar o Shodan."
    elif warning.kind == "network":
        base = f"{warning.ip}: falha de rede ao consultar o Shodan."
    elif warning.kind == "http":
        base = f"{warning.ip}: erro HTTP ao consultar o Shodan."
    elif warning.kind == "rate_limit":
        base = (
            f"Limite de requisições da API atingido ao consultar {warning.ip}. "
            "Aguarde alguns instantes antes de tentar novamente."
        )
    elif warning.kind == "domain_lookup":
        base = (
            f"{warning.ip}: não foi possível recuperar os IPs históricos do domínio via Shodan."
        )
    else:
        base = f"{warning.ip}: {warning.kind}."

    if verbose and warning.detail:
        base += f" Detalhes: {warning.detail}."
    return base

from __future__ import annotations

import base64
import html
import ipaddress
import json
import os
import re
import socket
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import requests
from fpdf import FPDF, XPos, YPos

from domain.entity import HostReport, ReportWarning, ServiceInfo, VulnerabilityDetail
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


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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
    pause: float = PAUSE_BETWEEN_REQUESTS,
) -> Tuple[List[HostReport], List[ReportWarning]]:
    ips = resolve_target(target)
    ips, domain_warnings = expand_ips_with_shodan_domain_data(target, ips, repository, timeout)
    host_reports: List[HostReport] = []
    warnings: List[ReportWarning] = domain_warnings
    for idx, ip in enumerate(ips, start=1):
        try:
            host_reports.append(repository.fetch_host_report(ip, timeout))
        except ValueError as not_found:
            warnings.append(ReportWarning(ip=ip, kind="not_found", detail=str(not_found)))
        except requests.Timeout:
            warnings.append(ReportWarning(ip=ip, kind="timeout"))
        except requests.HTTPError as http_err:
            status = http_err.response.status_code if http_err.response else None
            if status == 429:
                warnings.append(ReportWarning(ip=ip, kind="rate_limit", detail=str(status)))
                time.sleep(5)
                continue
            warnings.append(
                ReportWarning(ip=ip, kind="http", detail=str(status or http_err))
            )
        except requests.RequestException:
            warnings.append(ReportWarning(ip=ip, kind="network"))

        if idx < len(ips) and pause > 0:
            time.sleep(pause)
    return host_reports, warnings


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
    match = re.search(r"(\d{4})", vuln.cve)
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
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    result = []
    for year in ordered_years:
        severity_map = groups[year]
        ordered_map: Dict[str, List[VulnerabilityDetail]] = {}
        for sev in severity_order:
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


def rgb_to_hex(color: tuple[int, int, int]) -> str:
    return "#%02x%02x%02x" % color


class ReportPDF(FPDF):
    PAGE_BG = (247, 249, 252)
    HEADER_BG = (21, 35, 55)
    SECTION_BG = (227, 233, 242)
    CARD_BG = (255, 255, 255)
    CHIP_BG = (236, 240, 247)
    ACCENT = (28, 99, 189)
    TEXT_PRIMARY = (24, 32, 45)
    TEXT_MUTED = (110, 118, 138)
    BORDER_COLOR = (210, 216, 228)
    SEVERITY_COLORS = {
        "CRITICAL": (179, 38, 30),
        "HIGH": (227, 119, 15),
        "MEDIUM": (210, 155, 0),
        "LOW": (25, 118, 210),
        "INFO": (85, 139, 47),
    }
    BRAND_TITLE = "Surface vulnerability report"

    def __init__(self, brand_title: str | None = None) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.brand_title = brand_title or self.BRAND_TITLE
        self.header_height = 28
        self.header_enabled = True
        # Margens e quebra automática definem o layout base (mude aqui para espaçamentos globais)
        self.set_margins(20, 28, 20)
        self.set_auto_page_break(auto=True, margin=25)

    def header(self) -> None:  # pragma: no cover - visual helper
        if not getattr(self, "header_enabled", True):
            return
        # Fundo geral e barra superior – cobertura separada evita sobreposição visual
        body_height = max(self.h - self.header_height, 0)
        self.set_fill_color(*self.PAGE_BG)
        self.rect(0, self.header_height, self.w, body_height, "F")
        self.set_fill_color(*self.HEADER_BG)
        self.rect(0, 0, self.w, self.header_height, "F")
        self.set_text_color(255, 255, 255)
        self.set_xy(self.l_margin, 8)
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, self.brand_title, align="L")
        self.ln(8)
        # Garante que todo conteúdo da página comece abaixo do cabeçalho
        self.set_y(self.header_height + 8)

    def section_title(self, title: str, width: float, uppercase: bool = True) -> None:
        # Cabeçalho de cada seção – altere preenchimento/tipografia para um look diferente
        text = title.upper() if uppercase else title
        self.set_fill_color(*self.SECTION_BG)
        self.set_text_color(*self.TEXT_PRIMARY)
        self.set_font("Helvetica", "B", 13)
        self.cell(
            width,
            9,
            text,
            fill=True,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(2)


def create_bar_chart(
    labels: List[str],
    values: List[int],
    title: str,
    chart_paths: List[str],
) -> str | None:
    if not values or sum(values) == 0:
        return None
    fig, ax = plt.subplots(figsize=(2.8, 3.2))
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#f5f7fb")
    colors = ["#1c63bd", "#4b89dc", "#7aa7e8", "#a6c2f1"]
    bars = ax.bar(labels, values, color=colors[: len(labels)], edgecolor="#d0d8e6")
    ax.set_title(title, color="#1c2031", fontsize=10)
    ax.tick_params(colors="#1c2031", labelsize=8)
    for spine in ax.spines.values():
        spine.set_color("#cfd6e3")
    ax.bar_label(bars, padding=2, color="#1c2031", fontsize=8)
    fig.tight_layout()
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmp.name, dpi=220, bbox_inches="tight", transparent=True)
    plt.close(fig)
    chart_paths.append(tmp.name)
    return tmp.name


def create_summary_chart(hosts: List[HostReport], chart_paths: List[str]) -> str | None:
    total_hosts = len(hosts)
    total_ports = sum(len(set(host.open_ports)) for host in hosts)
    total_vulns = sum(len(host.vulns) for host in hosts)
    labels = ["Hosts", "Portas", "CVEs"]
    values = [total_hosts, total_ports, total_vulns]
    return create_bar_chart(labels, values, "Resumo do escopo", chart_paths)


def create_global_severity_chart(hosts: List[HostReport], chart_paths: List[str]) -> str | None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_counts: Dict[str, int] = {key: 0 for key in severity_order}
    for host in hosts:
        for vuln in host.vulns:
            severity = severity_from_cvss(cvss_score(vuln.cvss))
            severity_counts.setdefault(severity, 0)
            severity_counts[severity] += 1
        for service in host.services:
            for vuln in service.vulns:
                severity = severity_from_cvss(cvss_score(vuln.cvss))
                severity_counts.setdefault(severity, 0)
                severity_counts[severity] += 1

    labels = ["Crítico", "Alto", "Médio", "Baixo"]
    values = [severity_counts[key] for key in severity_order]
    colors = [rgb_to_hex(ReportPDF.SEVERITY_COLORS[key]) for key in severity_order]
    if not any(values):
        return None

    fig, ax = plt.subplots(figsize=(2.8, 2.8))
    fig.patch.set_facecolor("#ffffff")
    wedges, _ = ax.pie(values, colors=colors, startangle=90, wedgeprops={"linewidth": 0.5, "edgecolor": "#ffffff"})
    ax.axis('equal')
    for i, w in enumerate(wedges):
        if values[i] > 0:
            angle = (w.theta2 + w.theta1) / 2.0
            x = 0.65 * np.cos(np.deg2rad(angle))
            y = 0.65 * np.sin(np.deg2rad(angle))
            ax.text(
                x,
                y,
                str(values[i]),
                ha="center",
                va="center",
                color="#ffffff",
                fontsize=8,
                weight="bold",
            )
    ax.legend(wedges, labels, loc="lower center", bbox_to_anchor=(0.5, -0.18), ncol=4, fontsize=7)
    ax.set_title("Severidade total", fontsize=9, color="#1c2031")
    fig.tight_layout()
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmp.name, dpi=220, bbox_inches="tight", transparent=True)
    plt.close(fig)
    chart_paths.append(tmp.name)
    return tmp.name


def create_host_chart(host: HostReport, chart_paths: List[str]) -> str | None:
    labels = ["Portas", "CVEs"]
    values = [len(set(host.open_ports)), len(host.vulns)]
    return create_bar_chart(labels, values, f"Host {host.ip}", chart_paths)


def create_vuln_severity_chart(host: HostReport, chart_paths: List[str]) -> str | None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_counts: Dict[str, int] = {key: 0 for key in severity_order}
    for vuln in host.vulns:
        severity = severity_from_cvss(cvss_score(vuln.cvss))
        severity_counts.setdefault(severity, 0)
        severity_counts[severity] += 1
    for service in host.services:
        for vuln in service.vulns:
            severity = severity_from_cvss(cvss_score(vuln.cvss))
            severity_counts.setdefault(severity, 0)
            severity_counts[severity] += 1
    labels = ["Crítico", "Alto", "Médio", "Baixo"]
    values = [severity_counts[key] for key in severity_order]
    colors = [rgb_to_hex(ReportPDF.SEVERITY_COLORS[key]) for key in severity_order]
    if not any(values):
        return None
    fig, ax = plt.subplots(figsize=(2.6, 2.6))
    fig.patch.set_facecolor("#ffffff")
    wedges, texts = ax.pie(values, colors=colors, startangle=90, wedgeprops={"linewidth": 0.5, "edgecolor": "#ffffff"})
    ax.axis('equal')
    for i, w in enumerate(wedges):
        if values[i] > 0:
            angle = (w.theta2 + w.theta1) / 2.0
            x = 0.7 * np.cos(np.deg2rad(angle))
            y = 0.7 * np.sin(np.deg2rad(angle))
            ax.text(
                x,
                y,
                str(values[i]),
                ha="center",
                va="center",
                color="#ffffff",
                fontsize=8,
                weight="bold",
            )
    ax.legend(wedges, labels, loc="lower center", bbox_to_anchor=(0.5, -0.2), ncol=3, fontsize=7)
    ax.set_title("Severidade de CVEs", fontsize=9, color="#1c2031")
    fig.tight_layout()
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmp.name, dpi=220, bbox_inches="tight", transparent=True)
    plt.close(fig)
    chart_paths.append(tmp.name)
    return tmp.name


def render_pdf_bytes(target: str, hosts: List[HostReport], company: str | None = None) -> bytes:
    brand_name = (company or "SurfaceLens").strip() or "SurfaceLens"
    pdf = ReportPDF(brand_title=f"{brand_name} surface vulnerability report")
    chart_paths: List[str] = []
    generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    def render_cover_page() -> None:
        original_header = pdf.header_enabled
        pdf.header_enabled = False
        pdf.add_page()
        pdf.set_fill_color(18, 11, 15)
        pdf.rect(0, 0, pdf.w, pdf.h, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(pdf.l_margin, 60)
        cover_width = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_font("Helvetica", size=14)
        pdf.cell(cover_width, 8, f"{brand_name} | Relatório executivo", ln=1)
        pdf.ln(8)
        pdf.set_font("Helvetica", "B", 34)
        pdf.cell(cover_width, 16, brand_name.upper(), ln=1)
        pdf.cell(cover_width, 16, "SURFACE VULNERABILITY REPORT", ln=1)
        pdf.ln(6)
        pdf.set_draw_color(255, 255, 255)
        pdf.set_line_width(0.5)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(6)
        pdf.set_font("Helvetica", size=12)
        pdf.multi_cell(
            cover_width * 0.75,
            7,
            "Avaliação detalhada da superfície de ataque e vulnerabilidades priorizadas",
        )
        pdf.set_y(pdf.h - 60)
        pdf.set_font("Helvetica", size=11)
        pdf.multi_cell(cover_width, 6, f"Alvo: {target}")
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(cover_width, 6, f"Gerado em: {generated_at}", align="R")
        pdf.header_enabled = original_header

    def render_context_page() -> None:
        original_header = pdf.header_enabled
        pdf.header_enabled = False
        pdf.add_page()
        pdf.set_fill_color(*pdf.PAGE_BG)
        pdf.rect(0, 0, pdf.w, pdf.h, "F")
        pdf.set_text_color(*pdf.TEXT_PRIMARY)
        pdf.set_xy(pdf.l_margin, 35)
        context_width = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_font("Helvetica", "B", 20)
        pdf.ln(4)
        sections = [
            (
                "1. Introdução",
                [
                    "Apresentamos este relatório com uma análise da superfície de ataque da organização, identificando vulnerabilidades cibernéticas que podem ser exploradas por agentes maliciosos. O objetivo é avaliar riscos, priorizar correções e fortalecer a postura de segurança.",
                    "A superfície de ataque é o conjunto de todos os pontos de entrada potenciais que um invasor pode utilizar para comprometer sistemas, redes e aplicações.",
                ],
            ),
            (
                "2. Objetivo e Escopo",
                [
                    "O objetivo deste relatório é mapear e avaliar vulnerabilidades identificadas em ativos internos e externos, incluindo servidores, endpoints, APIs e recursos em nuvem.",
                    "O escopo da análise inclui ativos corporativos expostos à internet e infraestruturas críticas internas.",
                ],
            ),
        ]
        for title, paragraphs in sections:
            pdf.set_font("Helvetica", "B", 14)
            pdf.multi_cell(context_width, 8, title)
            pdf.ln(1)
            pdf.set_font("Helvetica", size=11)
            for paragraph in paragraphs:
                pdf.multi_cell(context_width, 6.2, paragraph)
                pdf.ln(2)
            pdf.ln(3)
        pdf.header_enabled = original_header

    def write_info_block(
        items: List[tuple[str, str | None, tuple[int, int, int] | None]],
        multiline: bool = True,
    ) -> None:
        for label, value, icon_color in items:
            if not value:
                continue
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*pdf.ACCENT)
            pdf.write(6, label.upper() + ": ")
            pdf.set_font("Helvetica", size=10)
            pdf.set_text_color(*pdf.TEXT_PRIMARY)
            if multiline:
                pdf.multi_cell(0, 6, value)
            else:
                pdf.write(6, value)
                pdf.ln(6)
            pdf.ln(1)

    def write_service_details(service: ServiceInfo) -> None:
        header_bits = [f"{service.port}/{service.transport or '?'}"]
        if service.product:
            header_bits.append(service.product)
        if service.version:
            header_bits.append(service.version)
        header_text = " | ".join(header_bits)

        pdf.set_fill_color(*pdf.CARD_BG)
        pdf.set_text_color(*pdf.TEXT_PRIMARY)
        pdf.set_font("Helvetica", "B", 11)

        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(content_width, 7, header_text, fill=True)

        details_lines: List[str] = []
        if service.info:
            details_lines.append("[INFO] " + service.info)
        if service.tags:
            details_lines.append("[TAGS] " + ", ".join(service.tags))
        if service.cpe:
            details_lines.append("[CPE] " + ", ".join(service.cpe))

        body_width = content_width - 8
        indent_x = pdf.l_margin + 4
        if details_lines:
            pdf.set_fill_color(*pdf.CHIP_BG)
            pdf.set_text_color(*pdf.TEXT_MUTED)
            pdf.set_font("Helvetica", size=9)
            for line in details_lines:
                pdf.set_x(indent_x)
                pdf.multi_cell(body_width, 5, line, fill=True)

        if service.vulns:
            for year, severity_map in group_vulns_by_year_and_severity(service.vulns):
                pdf.ln(2)
                pdf.set_fill_color(*pdf.SECTION_BG)
                pdf.set_text_color(*pdf.TEXT_PRIMARY)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_x(indent_x)
                pdf.multi_cell(body_width, 6, f"Vulnerabilidades {year}", fill=True)
                pdf.ln(1)
                for severity, entries in severity_map.items():
                    color = pdf.SEVERITY_COLORS.get(severity, pdf.TEXT_MUTED)
                    pdf.set_fill_color(*color)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.set_x(indent_x)
                    pdf.multi_cell(body_width, 5.5, severity.title(), fill=True)
                    pdf.set_text_color(*pdf.TEXT_PRIMARY)
                    pdf.set_font("Helvetica", size=9)
                    for idx_entry, vuln in enumerate(entries):
                        shade = pdf.CHIP_BG if idx_entry % 2 == 0 else (248, 250, 253)
                        pdf.set_fill_color(*shade)
                        pdf.set_x(indent_x)
                        pdf.multi_cell(body_width, 6, format_vuln_summary(vuln), fill=True)
                        pdf.set_y(pdf.get_y() + 1)
                    pdf.ln(2)
                pdf.ln(4)
        pdf.ln(4)

    def render_host(host: HostReport, idx: int) -> None:
        pdf.section_title(f"Host #{idx} - {host.ip}", content_width, uppercase=False)
        details: List[tuple[str, str | None, tuple[int, int, int] | None]] = [
            ("Hostnames", list_to_text(host.hostnames) or None, None),
            ("Organização", host.org, None),
            ("ISP", host.isp, None),
            ("Sistema Operacional", host.os, None),
            ("Localização", host.location, None),
            ("Tags", list_to_text(host.tags), None),
        ]
        if host.open_ports:
            details.append(("Portas abertas", ", ".join(str(p) for p in host.open_ports), None))
        all_vulns = collect_all_vulns(host)
        if all_vulns:
            details.append(("Vulnerabilidades", summarize_total_vulns(all_vulns), None))
        if not any(value for _, value, _ in details):
            details.append(("Informações", "Nenhum metadado divulgado pelo Shodan.", None))

        write_info_block(details)
        host_chart = create_host_chart(host, chart_paths)
        severity_chart = create_vuln_severity_chart(host, chart_paths)
        chart_width = (content_width - 6) / 2
        chart_height = 55
        chart_y = pdf.get_y()
        if host_chart:
            pdf.image(host_chart, x=pdf.l_margin, y=chart_y, w=chart_width, h=chart_height)
        if severity_chart:
            pdf.image(severity_chart, x=pdf.l_margin + chart_width + 6, y=chart_y, w=chart_width, h=chart_height)
        if host_chart or severity_chart:
            pdf.set_y(chart_y + chart_height + 6)
        pdf.section_title("Serviços expostos", content_width)
        if not host.services:
            pdf.set_fill_color(*pdf.CARD_BG)
            pdf.set_text_color(*pdf.TEXT_MUTED)
            pdf.set_font("Helvetica", size=10)
            pdf.multi_cell(
                content_width,
                6,
                "Nenhum serviço retornado pela API do Shodan.",
                fill=True,
            )
            pdf.ln(3)
        else:
            for service in host.services:
                write_service_details(service)
        pdf.ln(2)

    render_cover_page()
    render_context_page()

    pdf.header_enabled = True
    pdf.add_page()
    content_width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_text_color(*pdf.TEXT_PRIMARY)

    pdf.ln(4)
    pdf.section_title("Resumo do alvo", content_width)
    summary_items = [
        ("Alvo solicitado", target, None),
        ("Data de geração", generated_at, None),
        ("Hosts encontrados", str(len(hosts)), None),
    ]
    write_info_block(summary_items, multiline=False)
    summary_chart = create_summary_chart(hosts, chart_paths)
    severity_chart = create_global_severity_chart(hosts, chart_paths)
    if summary_chart or severity_chart:
        chart_width = (content_width - 6) / 2
        chart_height = 55
        y_start = pdf.get_y()
        if summary_chart:
            pdf.image(summary_chart, x=pdf.l_margin, y=y_start, w=chart_width, h=chart_height)
        if severity_chart:
            pdf.image(severity_chart, x=pdf.l_margin + chart_width + 6, y=y_start, w=chart_width, h=chart_height)
        pdf.set_y(y_start + chart_height + 6)

    pdf.add_page()

    for idx, host in enumerate(hosts, start=1):
        if idx > 1:
            pdf.add_page()
        render_host(host, idx)

    pdf_buffer = pdf.output(dest="S")
    if isinstance(pdf_buffer, str):
        output_bytes = pdf_buffer.encode("latin-1")
    else:
        output_bytes = bytes(pdf_buffer)

    for path in chart_paths:
        try:
            os.remove(path)
        except OSError:
            pass

    return output_bytes


def render_html_report(target: str, hosts: List[HostReport], company: str | None = None) -> str:
    """
    Gera um HTML imprimível (A4) com visual próximo ao PDF, usando Chart.js via CDN.
    """
    brand_name = (company or "SurfaceLens").strip() or "SurfaceLens"
    generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    def render_badge(label: str, color: str) -> str:
        return f'<span class="badge" style="background:{color};border-color:{color}">{html.escape(label)}</span>'

    def severity_color(sev: str) -> str:
        colors = {
            "CRITICAL": "#b3261e",
            "HIGH": "#e3770f",
            "MEDIUM": "#d29b00",
            "LOW": "#1976d2",
            "INFO": "#558b2f",
        }
        return colors.get(sev.upper(), "#374151")

    def severity_counts_for_host(host: HostReport) -> Dict[str, int]:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        counts = {key: 0 for key in order}
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

    def severity_counts_global(hosts: List[HostReport]) -> Dict[str, int]:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        counts = {key: 0 for key in order}
        for host in hosts:
            host_counts = severity_counts_for_host(host)
            for key, value in host_counts.items():
                counts.setdefault(key, 0)
                counts[key] += value
        return counts

    total_hosts = len(hosts)
    total_ports = sum(len(set(h.open_ports)) for h in hosts)
    total_vulns = sum(len(collect_all_vulns(h)) for h in hosts)

    host_sections: List[str] = []
    host_chart_data: List[Dict[str, Any]] = []
    severity_global = severity_counts_global(hosts)
    severity_labels_pt = ["Crítico", "Alto", "Médio", "Baixo"]
    severity_keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_colors = [severity_color(k) for k in severity_keys]

    for idx, host in enumerate(hosts, start=1):
        details: List[str] = []
        info_pairs = [
            ("Hostnames", list_to_text(host.hostnames) or None),
            ("Organização", host.org),
            ("ISP", host.isp),
            ("Sistema Operacional", host.os),
            ("Localização", host.location),
            ("Tags", list_to_text(host.tags)),
        ]
        if host.open_ports:
            info_pairs.append(("Portas abertas", ", ".join(str(p) for p in host.open_ports)))
        all_vulns = collect_all_vulns(host)
        if all_vulns:
            info_pairs.append(("Vulnerabilidades", summarize_total_vulns(all_vulns)))
        for label, value in info_pairs:
            if value:
                details.append(
                    f'<div class="info-row"><span class="info-label">{html.escape(label)}</span>'
                    f'<span class="info-value">{html.escape(value)}</span></div>'
                )

        service_blocks: List[str] = []
        for service in host.services:
            header_bits = [f"{service.port}/{service.transport or '?'}"]
            if service.product:
                header_bits.append(service.product)
            if service.version:
                header_bits.append(service.version)
            header_text = " | ".join(header_bits)
            meta_lines: List[str] = []
            if service.info:
                meta_lines.append(f"<strong>Info:</strong> {html.escape(service.info)}")
            if service.tags:
                meta_lines.append(f"<strong>Tags:</strong> {html.escape(', '.join(service.tags))}")
            if service.cpe:
                meta_lines.append(f"<strong>CPE:</strong> {html.escape(', '.join(service.cpe))}")

            vuln_html: List[str] = []
            if service.vulns:
                for year, severity_map in group_vulns_by_year_and_severity(service.vulns):
                    vuln_html.append(f'<div class="vuln-year">Vulnerabilidades {html.escape(year)}</div>')
                    for severity, entries in severity_map.items():
                        color = severity_color(severity)
                        vuln_html.append(f'<div class="vuln-severity">{render_badge(severity.title(), color)}</div>')
                        for vuln in entries:
                            vuln_html.append(
                                f'<div class="vuln-entry">{html.escape(format_vuln_summary(vuln))}</div>'
                            )

            service_blocks.append(
                f"""
                <div class="service-card">
                  <div class="service-header">{html.escape(header_text)}</div>
                  {'<div class="service-meta">' + '<br>'.join(meta_lines) + '</div>' if meta_lines else ''}
                  {'<div class="vuln-list">' + ''.join(vuln_html) + '</div>' if vuln_html else ''}
                </div>
                """
            )

        host_sev_counts = severity_counts_for_host(host)
        host_chart_id = f"chart-host-{idx}"
        host_sev_id = f"chart-host-sev-{idx}"
        host_chart_data.append(
            {
                "chartId": host_chart_id,
                "labels": ["Portas", "CVEs"],
                "values": [len(set(host.open_ports)), len(all_vulns)],
                "severityId": host_sev_id,
                "severityLabels": severity_labels_pt,
                "severityValues": [host_sev_counts.get(key, 0) for key in severity_keys],
                "severityColors": severity_colors,
            }
        )

        charts_html = f"""
        <div class='chart-grid'>
          <div class="chart-card"><canvas id='{host_chart_id}' aria-label='Resumo do host'></canvas></div>
          <div class="chart-card"><canvas id='{host_sev_id}' aria-label='Severidade do host'></canvas></div>
        </div>
        """

        host_sections.append(
            f"""
            <section class="host-section">
              <div class="section-title">Host #{idx} — {html.escape(host.ip)}</div>
              <div class="info-grid">{''.join(details) or '<p class="muted">Nenhum metadado disponível.</p>'}</div>
              {charts_html}
              <div class="section-subtitle">Serviços expostos</div>
              {'<div class="services-grid">' + ''.join(service_blocks) + '</div>' if service_blocks else '<p class="muted">Nenhum serviço retornado.</p>'}
            </section>
            """
        )

    charts_payload = {
        "summary": {"labels": ["Hosts", "Portas", "CVEs"], "values": [total_hosts, total_ports, total_vulns]},
        "globalSeverity": {
            "labels": severity_labels_pt,
            "values": [severity_global.get(key, 0) for key in severity_keys],
            "colors": severity_colors,
        },
        "hosts": host_chart_data,
    }
    charts_json = json.dumps(charts_payload)
    charts_b64 = base64.b64encode(charts_json.encode("utf-8")).decode("ascii")

    html_output = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(brand_name)} - Surface Lens</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #120609;
      --panel: #211319;
      --card: #1b0f14;
      --muted: #c7b7b2;
      --text: #f9f5f3;
      --accent: #ff6f61;
      --accent-soft: #ff968a;
      --border: #2a1820;
      --shadow: 0 20px 60px rgba(0,0,0,0.35);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 24px;
      font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }}
    @page {{
      size: A4;
      margin: 18mm;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .hero {{
      background: radial-gradient(circle at 20% 20%, rgba(255,150,138,0.16), transparent 25%),
                  radial-gradient(circle at 80% 0%, rgba(255,111,97,0.18), transparent 25%),
                  linear-gradient(135deg, #1a0d12, #120609);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 24px;
      box-shadow: var(--shadow);
    }}
    .hero-title {{ font-size: 26px; font-weight: 700; margin: 0 0 8px; }}
    .hero-sub {{ color: var(--muted); margin: 0 0 4px; font-size: 14px; }}
    .hero-meta {{ display: flex; gap: 12px; flex-wrap: wrap; color: var(--muted); font-size: 13px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; color: #fff; font-size: 12px; border: 1px solid transparent; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      box-shadow: var(--shadow);
    }}
    .card-title {{ font-size: 13px; color: var(--muted); margin: 0 0 4px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .card-value {{ font-size: 22px; font-weight: 700; margin: 0; }}
    .section-title {{
      font-size: 18px;
      font-weight: 700;
      margin: 28px 0 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
    }}
    .section-subtitle {{ font-weight: 700; margin: 18px 0 8px; }}
    .chart-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; margin: 12px 0; }}
    .chart-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 10px; }}
    .chart-card canvas {{ width: 100% !important; height: 240px !important; display: block; }}
    .host-section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px;
      box-shadow: var(--shadow);
      margin-top: 20px;
    }}
    .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 8px; }}
    .info-row {{ background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 10px; padding: 10px; }}
    .info-label {{ display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }}
    .info-value {{ font-size: 14px; font-weight: 600; }}
    .services-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; }}
    .service-card {{ background: #0f172a; border: 1px solid var(--border); border-radius: 12px; padding: 10px; }}
    .service-header {{ font-weight: 700; margin-bottom: 6px; }}
    .service-meta {{ font-size: 13px; color: var(--muted); margin-bottom: 6px; }}
    .vuln-list {{ display: grid; gap: 6px; }}
    .vuln-year {{ font-weight: 700; margin-top: 6px; }}
    .vuln-severity {{ margin: 2px 0; }}
    .vuln-entry {{ background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 8px; padding: 6px 8px; font-size: 13px; }}
    .muted {{ color: var(--muted); }}
    @media print {{
      body {{ background: #fff; color: #111827; }}
      .hero, .card, .host-section, .service-card {{ box-shadow: none; background: #fff; border-color: #e5e7eb; }}
      .chart-img {{ background: #fff; border-color: #e5e7eb; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="hero">
      <p class="hero-sub">Surface Lens</p>
      <h1 class="hero-title">{html.escape(brand_name)} — Surface vulnerability report</h1>
      <p class="hero-sub">Alvo: {html.escape(target)}</p>
      <div class="hero-meta">
        <span>Gerado em: {html.escape(generated_at)}</span>
      </div>
    </header>

    <section>
      <div class="cards">
        <div class="card"><div class="card-title">Hosts encontrados</div><div class="card-value">{total_hosts}</div></div>
        <div class="card"><div class="card-title">Portas únicas</div><div class="card-value">{total_ports}</div></div>
        <div class="card"><div class="card-title">Total de CVEs</div><div class="card-value">{total_vulns}</div></div>
      </div>
      <div class='chart-grid'>
        <div class="chart-card"><canvas id="chart-summary" aria-label="Resumo do escopo"></canvas></div>
        <div class="chart-card"><canvas id="chart-severity-global" aria-label="Severidade global"></canvas></div>
      </div>
    </section>
    {''.join(host_sections)}
  </div>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    const chartData = JSON.parse(atob("{charts_b64}"));
    const colorPalette = ["#ff6f61", "#ff968a", "#ffc7b8", "#b23c34"];

    function renderBar(id, labels, values, colors) {{
      const ctx = document.getElementById(id);
      if (!ctx) return;
      new Chart(ctx, {{
        type: 'bar',
        data: {{
          labels,
          datasets: [{{
            data: values,
            backgroundColor: colors,
            borderRadius: 6,
          }}],
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          plugins: {{
            legend: {{ display: false }},
            tooltip: {{
              backgroundColor: '#1b0f14',
              borderColor: '#2a1820',
              borderWidth: 1,
            }},
          }},
          scales: {{
            x: {{
              grid: {{ color: 'rgba(255,255,255,0.08)' }},
              ticks: {{ color: '#f9f5f3' }},
            }},
            y: {{
              beginAtZero: true,
              grid: {{ color: 'rgba(255,255,255,0.08)' }},
              ticks: {{ color: '#f9f5f3', stepSize: 1 }},
            }},
          }},
        }},
      }});
    }}

    function renderDoughnut(id, labels, values, colors) {{
      const ctx = document.getElementById(id);
      if (!ctx) return;
      new Chart(ctx, {{
        type: 'doughnut',
        data: {{
          labels,
          datasets: [{{
            data: values,
            backgroundColor: colors,
            borderColor: '#0f172a',
            borderWidth: 2,
          }}],
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          cutout: '55%',
          plugins: {{
            legend: {{ position: 'bottom', labels: {{ color: '#f9f5f3' }} }},
            tooltip: {{
              backgroundColor: '#1b0f14',
              borderColor: '#2a1820',
              borderWidth: 1,
            }},
          }},
        }},
      }});
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      renderBar('chart-summary', chartData.summary.labels, chartData.summary.values, colorPalette);
      renderDoughnut('chart-severity-global', chartData.globalSeverity.labels, chartData.globalSeverity.values, chartData.globalSeverity.colors);
      chartData.hosts.forEach((host) => {{
        renderBar(host.chartId, host.labels, host.values, colorPalette.slice(0, host.labels.length));
        renderDoughnut(host.severityId, host.severityLabels, host.severityValues, host.severityColors);
      }});
    }});
  </script>
</body>
</html>
"""
    return html_output


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

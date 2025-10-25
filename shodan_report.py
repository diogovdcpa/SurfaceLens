from __future__ import annotations

import ipaddress
import os
import re
import socket
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import requests
from fpdf import FPDF, XPos, YPos

API_BASE_URL = "https://api.shodan.io"
DEFAULT_TIMEOUT = 60
MAX_TARGET_IPS = 1024
PAUSE_BETWEEN_REQUESTS = 1.0


@dataclass
class VulnerabilityDetail:
    cve: str
    cvss: float | str | None = None
    verified: bool | None = None
    references: List[str] = field(default_factory=list)


@dataclass
class ServiceInfo:
    port: int
    transport: str
    product: str | None
    version: str | None
    cpe: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    vulns: List[VulnerabilityDetail] = field(default_factory=list)
    info: str | None = None


@dataclass
class HostReport:
    ip: str
    hostnames: List[str]
    org: str | None
    isp: str | None
    os: str | None
    location: str | None
    open_ports: List[int]
    tags: List[str]
    vulns: List[VulnerabilityDetail]
    services: List[ServiceInfo]


@dataclass
class ReportWarning:
    ip: str
    kind: str
    detail: str | None = None


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

    def __init__(self) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        # Margens e quebra automática definem o layout base (mude aqui para espaçamentos globais)
        self.set_margins(20, 34, 20)
        self.set_auto_page_break(auto=True, margin=25)

    def __init__(self, logo_path: str | None = None) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.logo_path = logo_path
        self.header_height = 28
        # Margens e quebra automática definem o layout base (mude aqui para espaçamentos globais)
        self.set_margins(20, 28, 20)
        self.set_auto_page_break(auto=True, margin=25)

    def header(self) -> None:  # pragma: no cover - visual helper
        # Fundo geral e barra superior – ajuste as cores para alterar a paleta
        self.set_fill_color(*self.PAGE_BG)
        self.rect(0, 0, self.w, self.h, "F")
        self.set_fill_color(*self.HEADER_BG)
        self.rect(0, 0, self.w, self.header_height, "F")
        self.set_draw_color(*self.BORDER_COLOR)
        self.line(self.l_margin, self.header_height, self.w - self.r_margin, self.header_height)
        self.set_text_color(255, 255, 255)
        self.set_xy(self.l_margin, 8)
        logo_width = 20
        if self.logo_path:
            try:
                self.image(self.logo_path, x=self.l_margin, y=6, h=18)
                self.set_xy(self.l_margin + logo_width + 4, 9)
            except Exception:
                self.set_xy(self.l_margin, 9)
        else:
            self.set_xy(self.l_margin, 9)
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "SurfaceLens Report", align="L")
        self.ln(8)
        # Garante que todo conteúdo da página comece abaixo do cabeçalho
        self.set_y(self.header_height + 4)

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


def load_api_key(cli_value: str | None) -> str:
    api_key = cli_value or os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("Informe a chave do Shodan via parâmetro ou variável SHODAN_API_KEY")
    return api_key


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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


def shodan_request(path: str, api_key: str, timeout: int) -> Dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    params = {"key": api_key}
    response = requests.get(url, params=params, timeout=timeout)
    if response.status_code == 404:
        raise ValueError("Alvo não encontrado no Shodan")
    response.raise_for_status()
    return response.json()


def normalize_references(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def build_vuln_detail(identifier: str, data: Any) -> VulnerabilityDetail:
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


def extract_vulns(raw: Any) -> List[VulnerabilityDetail]:
    findings: List[VulnerabilityDetail] = []
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
    total_services = sum(len(host.services) for host in hosts)
    total_vulns = sum(len(host.vulns) for host in hosts)
    labels = ["Hosts", "Portas", "Serviços", "CVEs"]
    values = [total_hosts, total_ports, total_services, total_vulns]
    return create_bar_chart(labels, values, "Resumo do escopo", chart_paths)


def create_host_chart(host: HostReport, chart_paths: List[str]) -> str | None:
    labels = ["Portas", "Serviços", "CVEs"]
    values = [len(set(host.open_ports)), len(host.services), len(host.vulns)]
    return create_bar_chart(labels, values, f"Host {host.ip}", chart_paths)


def create_vuln_severity_chart(host: HostReport, chart_paths: List[str]) -> str | None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_counts: Dict[str, int] = {key: 0 for key in severity_order}
    for vuln in host.vulns:
        severity = severity_from_cvss(cvss_score(vuln.cvss))
        severity_counts[severity] += 1
    labels = ["Crítico", "Alto", "Médio", "Baixo", "Info"]
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


def fetch_host_report(ip: str, api_key: str, timeout: int) -> HostReport:
    payload = shodan_request(f"/shodan/host/{ip}", api_key, timeout)
    services: List[ServiceInfo] = []
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


def slugify(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe.strip("-_.") or "alvo"


def default_output_name(target: str) -> str:
    slug = slugify(target)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"relatorio-shodan-{slug}-{timestamp}.pdf"


def list_to_text(values: Sequence[str]) -> str | None:
    if not values:
        return None
    return ", ".join(values)


def render_pdf_bytes(target: str, hosts: List[HostReport]) -> bytes:
    logo_path = Path(__file__).with_name("static").joinpath("surfacelens-logo.svg")
    pdf = ReportPDF(logo_path=str(logo_path) if logo_path.exists() else None)
    chart_paths: List[str] = []
    pdf.add_page()
    content_width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_text_color(*pdf.TEXT_PRIMARY)

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

    generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    pdf.ln(4)
    pdf.section_title("Resumo do alvo", content_width)
    summary_items = [
        ("Alvo solicitado", target, None),
        ("Data de geração", generated_at, None),
        ("Hosts encontrados", str(len(hosts)), None),
    ]
    write_info_block(summary_items, multiline=False)
    summary_chart = create_summary_chart(hosts, chart_paths)
    if summary_chart:
        chart_width = content_width / 2
        chart_x = pdf.l_margin + (content_width - chart_width) / 2
        pdf.image(summary_chart, x=chart_x, w=chart_width, h=50)
        pdf.ln(10)

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


def collect_host_reports(
    target: str,
    api_key: str,
    timeout: int = DEFAULT_TIMEOUT,
    pause: float = PAUSE_BETWEEN_REQUESTS,
) -> Tuple[List[HostReport], List[ReportWarning]]:
    ips = resolve_target(target)
    host_reports: List[HostReport] = []
    warnings: List[ReportWarning] = []
    for idx, ip in enumerate(ips, start=1):
        try:
            host_reports.append(fetch_host_report(ip, api_key, timeout))
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
    else:
        base = f"{warning.ip}: {warning.kind}."

    if verbose and warning.detail:
        base += f" Detalhes: {warning.detail}."
    return base

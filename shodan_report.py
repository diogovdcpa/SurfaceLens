from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import requests
from fpdf import FPDF, XPos, YPos

API_BASE_URL = "https://api.shodan.io"
DEFAULT_TIMEOUT = 20
MAX_TARGET_IPS = 1024


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
    PAGE_BG = (34, 9, 12)
    HEADER_BG = (89, 15, 22)
    SECTION_BG = (122, 26, 35)
    CARD_BG = (61, 20, 27)
    CHIP_BG = (82, 28, 35)
    ACCENT = (255, 150, 138)
    TEXT_PRIMARY = (249, 245, 245)
    TEXT_MUTED = (222, 209, 209)
    SEVERITY_COLORS = {
        "CRITICAL": (219, 68, 55),
        "HIGH": (244, 143, 0),
        "MEDIUM": (244, 180, 0),
        "LOW": (66, 133, 244),
        "INFO": (156, 39, 176),
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
        self.set_text_color(*self.TEXT_PRIMARY)
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


def summarize_vulns_by_year(vulns: List[VulnerabilityDetail]) -> str:
    if not vulns:
        return ""
    pieces: List[str] = []
    for year, severity_map in group_vulns_by_year_and_severity(vulns):
        counts = [f"{sev.title()}: {len(items)}" for sev, items in severity_map.items()]
        if counts:
            pieces.append(f"{year} ({', '.join(counts)})")
    return "; ".join(pieces)


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

    return HostReport(
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
    pdf.add_page()
    content_width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_text_color(*pdf.TEXT_PRIMARY)

    def write_info_block(
        items: List[tuple[str, str | None, tuple[int, int, int] | None]],
        multiline: bool = True,
    ) -> None:
        label_width = 45
        value_width = content_width - label_width
        icon_size = 5.5
        for label, value, icon_color in items:
            if not value:
                continue
            current_y = pdf.get_y()
            text_start = pdf.l_margin
            if icon_color:
                pdf.set_fill_color(*icon_color)
                pdf.ellipse(pdf.l_margin, current_y + 2, icon_size, icon_size, "F")
                text_start += icon_size + 3

            label_width_adjusted = label_width - (text_start - pdf.l_margin)
            pdf.set_xy(text_start, current_y)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*pdf.ACCENT)
            pdf.cell(label_width_adjusted, 6, label.upper(), align="L")
            pdf.set_font("Helvetica", size=10)
            pdf.set_text_color(*pdf.TEXT_PRIMARY)
            pdf.set_xy(pdf.l_margin + label_width, current_y)
            if multiline:
                pdf.multi_cell(value_width, 6, value)
                pdf.ln(0.5)
            else:
                pdf.cell(value_width, 6, value, ln=True)
        pdf.ln(2)

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
                pdf.set_fill_color(*pdf.CARD_BG)
                pdf.set_text_color(*pdf.TEXT_PRIMARY)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_x(indent_x)
                pdf.multi_cell(body_width, 5, f"Vulnerabilidades {year}", fill=True)
                for severity, entries in severity_map.items():
                    color = pdf.SEVERITY_COLORS.get(severity, pdf.TEXT_MUTED)
                    pdf.set_fill_color(*pdf.CHIP_BG)
                    pdf.set_text_color(*color)
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.set_x(indent_x)
                    pdf.multi_cell(body_width, 5, severity.title(), fill=True)
                    pdf.set_text_color(*pdf.TEXT_MUTED)
                    pdf.set_font("Helvetica", size=9)
                    for vuln in entries:
                        pdf.set_x(indent_x)
                        pdf.multi_cell(body_width, 5, format_vuln_summary(vuln), fill=True)
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
        if host.vulns:
            details.append(("Vulnerabilidades", summarize_vulns_by_year(host.vulns), None))
        if not any(value for _, value, _ in details):
            details.append(("Informações", "Nenhum metadado divulgado pelo Shodan.", None))

        write_info_block(details)
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

    for idx, host in enumerate(hosts, start=1):
        render_host(host, idx)

    pdf_buffer = pdf.output(dest="S")
    if isinstance(pdf_buffer, str):
        return pdf_buffer.encode("latin-1")
    return bytes(pdf_buffer)


def collect_host_reports(
    target: str, api_key: str, timeout: int = DEFAULT_TIMEOUT
) -> Tuple[List[HostReport], List[ReportWarning]]:
    ips = resolve_target(target)
    host_reports: List[HostReport] = []
    warnings: List[ReportWarning] = []
    for ip in ips:
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
                break
            warnings.append(
                ReportWarning(ip=ip, kind="http", detail=str(status or http_err))
            )
        except requests.RequestException:
            warnings.append(ReportWarning(ip=ip, kind="network"))
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

from __future__ import annotations

import os
import tempfile
from typing import List

from fpdf import FPDF, XPos, YPos

from application.report_models import ReportHost, ReportModel
from application.report_utils import (
    format_vuln_summary,
    group_vulns_by_year_and_severity,
    list_to_text,
    summarize_total_vulns,
)

_MPL_READY = False


def _ensure_matplotlib() -> None:
    global _MPL_READY
    if _MPL_READY:
        return
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")
    import matplotlib

    matplotlib.use("Agg")
    _MPL_READY = True


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
        # Fundo geral e barra superior - cobertura separada evita sobreposicao visual
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
        # Garante que todo conteudo da pagina comece abaixo do cabecalho
        self.set_y(self.header_height + 8)

    def section_title(self, title: str, width: float, uppercase: bool = True) -> None:
        # Cabecalho de cada secao - altere preenchimento/tipografia para um look diferente
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
    _ensure_matplotlib()
    import matplotlib.pyplot as plt

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


def create_summary_chart(report: ReportModel, chart_paths: List[str]) -> str | None:
    labels = ["Hosts", "Portas", "CVEs (24h)"]
    values = [
        report.summary.total_hosts,
        report.summary.total_ports,
        report.summary.total_vulns_24h,
    ]
    return create_bar_chart(labels, values, "Resumo do escopo", chart_paths)


def create_global_severity_chart(report: ReportModel, chart_paths: List[str]) -> str | None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt
    import numpy as np

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_counts = report.summary.severity_24h

    labels = ["Crítico", "Alto", "Médio", "Baixo"]
    values = [severity_counts.get(key, 0) for key in severity_order]
    colors = [rgb_to_hex(ReportPDF.SEVERITY_COLORS[key]) for key in severity_order]
    if not any(values):
        return None

    fig, ax = plt.subplots(figsize=(2.8, 2.8))
    fig.patch.set_facecolor("#ffffff")
    wedges, _ = ax.pie(values, colors=colors, startangle=90, wedgeprops={"linewidth": 0.5, "edgecolor": "#ffffff"})
    ax.axis("equal")
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
    ax.set_title("Severidade (24h)", fontsize=9, color="#1c2031")
    fig.tight_layout()
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmp.name, dpi=220, bbox_inches="tight", transparent=True)
    plt.close(fig)
    chart_paths.append(tmp.name)
    return tmp.name


def create_host_chart(host: ReportHost, chart_paths: List[str]) -> str | None:
    labels = ["Portas", "CVEs (24h)"]
    values = [host.unique_ports, len(host.recent_vulns)]
    return create_bar_chart(labels, values, f"Host {host.host.ip}", chart_paths)


def create_vuln_severity_chart(host: ReportHost, chart_paths: List[str]) -> str | None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt
    import numpy as np

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_counts = host.recent_severity_counts
    labels = ["Crítico", "Alto", "Médio", "Baixo"]
    values = [severity_counts.get(key, 0) for key in severity_order]
    colors = [rgb_to_hex(ReportPDF.SEVERITY_COLORS[key]) for key in severity_order]
    if not any(values):
        return None
    fig, ax = plt.subplots(figsize=(2.6, 2.6))
    fig.patch.set_facecolor("#ffffff")
    wedges, _ = ax.pie(values, colors=colors, startangle=90, wedgeprops={"linewidth": 0.5, "edgecolor": "#ffffff"})
    ax.axis("equal")
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
    ax.set_title("Severidade (24h)", fontsize=9, color="#1c2031")
    fig.tight_layout()
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmp.name, dpi=220, bbox_inches="tight", transparent=True)
    plt.close(fig)
    chart_paths.append(tmp.name)
    return tmp.name


def render_pdf_bytes(report: ReportModel) -> bytes:
    brand_name = report.company
    pdf = ReportPDF(brand_title=f"{brand_name} surface vulnerability report")
    chart_paths: List[str] = []
    generated_at = report.generated_at.strftime("%d/%m/%Y %H:%M UTC")
    severity_labels = [
        ("Crítico", "CRITICAL"),
        ("Alto", "HIGH"),
        ("Médio", "MEDIUM"),
        ("Baixo", "LOW"),
        ("Info", "INFO"),
    ]

    def format_severity_counts(counts: dict[str, int]) -> str | None:
        parts = []
        for label, key in severity_labels:
            value = counts.get(key, 0)
            if value:
                parts.append(f"{label}: {value}")
        return " | ".join(parts) if parts else None

    def format_recent_cves(recent) -> str | None:
        if not recent:
            return None
        return ", ".join(vuln.cve for vuln in recent)

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
        pdf.multi_cell(cover_width, 6, f"Alvo: {report.target}")
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

    def write_service_details(service) -> None:
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

    def render_host(host: ReportHost, idx: int) -> None:
        data = host.host
        pdf.section_title(f"Host #{idx} - {data.ip}", content_width, uppercase=False)
        details: List[tuple[str, str | None, tuple[int, int, int] | None]] = [
            ("Hostnames", list_to_text(data.hostnames) or None, None),
            ("Organização", data.org, None),
            ("ISP", data.isp, None),
            ("Sistema Operacional", data.os, None),
            ("Localização", data.location, None),
            ("Tags", list_to_text(data.tags), None),
        ]
        if data.open_ports:
            details.append(("Portas abertas (agora)", ", ".join(str(p) for p in data.open_ports), None))
        if host.all_vulns:
            details.append(("Vulnerabilidades (total)", summarize_total_vulns(host.all_vulns), None))
        recent_cves = format_recent_cves(host.recent_vulns)
        details.append(("CVEs (24h)", recent_cves or "Nenhuma nas últimas 24h", None))
        severity_text = format_severity_counts(host.recent_severity_counts)
        details.append(("Severidade (24h)", severity_text or "Sem dados nas últimas 24h", None))
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
        if not data.services:
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
            for service in data.services:
                write_service_details(service)
        pdf.ln(2)
        if data.history_detail:
            pdf.section_title("Histórico (últimos 3 anos)", content_width)
            for item in data.history_detail:
                period = item.get("period") or "-"
                ports = item.get("ports") or []
                cves = item.get("cves") or []
                severity = item.get("severity") or {}
                ports_text = ", ".join(str(p) for p in ports) if ports else "-"
                cves_text = ", ".join(str(c) for c in cves) if cves else "-"
                severity_text = format_severity_counts(severity) or "-"
                pdf.set_fill_color(*pdf.CARD_BG)
                pdf.set_text_color(*pdf.TEXT_PRIMARY)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(content_width, 6, f"Período {period}", fill=True)
                pdf.set_font("Helvetica", size=9)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(content_width, 5, f"Portas: {ports_text}")
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(content_width, 5, f"CVEs: {cves_text}")
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(content_width, 5, f"Severidade: {severity_text}")
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
        ("Alvo solicitado", report.target, None),
        ("Data de geração", generated_at, None),
        ("Hosts encontrados", str(report.summary.total_hosts), None),
        ("Portas abertas (escopo)", str(report.summary.total_ports), None),
        ("CVEs (24h)", str(report.summary.total_vulns_24h), None),
        (
            "Severidade (24h)",
            format_severity_counts(report.summary.severity_24h) or "Sem dados nas últimas 24h",
            None,
        ),
        ("Modo histórico", "Ativado" if report.summary.history_enabled else "Desativado", None),
    ]
    write_info_block(summary_items, multiline=False)
    summary_chart = create_summary_chart(report, chart_paths)
    severity_chart = create_global_severity_chart(report, chart_paths)
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

    for idx, host in enumerate(report.hosts, start=1):
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

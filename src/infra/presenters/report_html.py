from __future__ import annotations

import base64
import html
import json
from typing import Any, Dict, List

from application.report_models import ReportModel
from application.report_utils import (
    format_vuln_summary,
    group_vulns_by_year_and_severity,
    list_to_text,
)


def render_html_report(report: ReportModel) -> str:
    """
    Gera um HTML imprimivel (A4) com visual proximo ao PDF, usando Chart.js via CDN.
    """
    brand_name = report.company
    generated_at = report.generated_at.strftime("%d/%m/%Y %H:%M UTC")

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

    severity_labels = [
        ("Crítico", "CRITICAL"),
        ("Alto", "HIGH"),
        ("Médio", "MEDIUM"),
        ("Baixo", "LOW"),
        ("Info", "INFO"),
    ]

    def format_severity_counts(counts: Dict[str, int]) -> str | None:
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

    total_hosts = report.summary.total_hosts
    total_ports = report.summary.total_ports
    total_vulns_24h = report.summary.total_vulns_24h

    host_sections: List[str] = []
    host_chart_data: List[Dict[str, Any]] = []
    severity_global = report.summary.severity_24h
    severity_labels_pt = ["Crítico", "Alto", "Médio", "Baixo"]
    severity_keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_colors = [severity_color(k) for k in severity_keys]

    for idx, host_item in enumerate(report.hosts, start=1):
        host = host_item.host
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
        if host_item.all_vulns:
            info_pairs.append(("Vulnerabilidades (total)", f"{len(host_item.all_vulns)}"))
        recent_cves = format_recent_cves(host_item.recent_vulns)
        info_pairs.append(("CVEs (24h)", recent_cves or "Nenhuma nas últimas 24h"))
        severity_24h_text = format_severity_counts(host_item.recent_severity_counts)
        info_pairs.append(("Severidade (24h)", severity_24h_text or "Sem dados nas últimas 24h"))
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
                <div class=\"service-card\">
                  <div class=\"service-header\">{html.escape(header_text)}</div>
                  {'<div class="service-meta">' + '<br>'.join(meta_lines) + '</div>' if meta_lines else ''}
                  {'<div class="vuln-list">' + ''.join(vuln_html) + '</div>' if vuln_html else ''}
                </div>
                """
            )

        host_chart_id = f"chart-host-{idx}"
        host_sev_id = f"chart-host-sev-{idx}"
        trend_data = host.history_trend or {}
        trend_labels = trend_data.get("labels") or []
        trend_id = f"chart-host-trend-{idx}" if trend_labels else None
        host_chart_data.append(
            {
                "chartId": host_chart_id,
                "labels": ["Portas", "CVEs (24h)"],
                "values": [host_item.unique_ports, len(host_item.recent_vulns)],
                "severityId": host_sev_id,
                "severityLabels": severity_labels_pt,
                "severityValues": [host_item.recent_severity_counts.get(key, 0) for key in severity_keys],
                "severityColors": severity_colors,
                "trend": {
                    "id": trend_id,
                    "labels": trend_labels,
                    "ports": trend_data.get("ports") or [],
                    "cves": trend_data.get("cves") or [],
                }
                if trend_id
                else None,
            }
        )

        charts_html = "<div class='chart-grid'>"
        charts_html += f"<div class=\"chart-card\"><canvas id='{host_chart_id}' aria-label='Resumo do host (24h)'></canvas></div>"
        charts_html += f"<div class=\"chart-card\"><canvas id='{host_sev_id}' aria-label='Severidade do host (24h)'></canvas></div>"
        if trend_id:
            charts_html += f"<div class=\"chart-card\"><canvas id='{trend_id}' aria-label='Tendência histórica do host'></canvas></div>"
        charts_html += "</div>"

        history_html = ""
        if host.history_detail:
            rows = []
            for item in host.history_detail:
                ports_text = ", ".join(str(p) for p in item.get("ports", [])) if item.get("ports") else "—"
                cves_text = ", ".join(html.escape(c) for c in item.get("cves", [])) if item.get("cves") else "—"
                severity_text = format_severity_counts(item.get("severity", {})) or "—"
                rows.append(
                    f"<div class='history-row'>"
                    f"<div class='history-period'>{html.escape(str(item.get('period') or ''))}</div>"
                    f"<div class='history-ports'><strong>Portas:</strong> {ports_text}</div>"
                    f"<div class='history-cves'><strong>CVEs:</strong> {cves_text}</div>"
                    f"<div class='history-severity'><strong>Severidade:</strong> {html.escape(severity_text)}</div>"
                    f"</div>"
                )
            history_html = (
                "<div class=\"section-subtitle\">Histórico detalhado (últimos 3 anos)</div>"
                "<div class=\"history-table\">"
                + "".join(rows)
                + "</div>"
            )

        host_sections.append(
            f"""
            <section class=\"host-section\">
              <div class=\"section-title\">Host #{idx} — {html.escape(host.ip)}</div>
              <div class=\"info-grid\">{''.join(details) or '<p class="muted">Nenhum metadado disponível.</p>'}</div>
              {charts_html}
              <div class=\"section-subtitle\">Serviços expostos</div>
              {'<div class="services-grid">' + ''.join(service_blocks) + '</div>' if service_blocks else '<p class="muted">Nenhum serviço retornado.</p>'}
              {history_html}
            </section>
            """
        )

    charts_payload = {
        "summary": {
            "labels": ["Hosts", "Portas", "CVEs (24h)"],
            "values": [total_hosts, total_ports, total_vulns_24h],
        },
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
    .context {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px;
      box-shadow: var(--shadow);
      margin: 20px 0;
    }}
    .context-title {{ font-size: 18px; font-weight: 700; margin: 0 0 10px; }}
    .context p {{ margin: 0 0 10px; color: var(--muted); }}
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
    .history-table {{ display: grid; gap: 8px; margin-top: 12px; }}
    .history-row {{ display: grid; grid-template-columns: 1fr 2fr 2fr 2fr; gap: 8px; background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 10px; padding: 8px; }}
    .history-period {{ font-weight: 700; }}
    .history-ports, .history-cves, .history-severity {{ font-size: 13px; }}
    @media (max-width: 768px) {{
      .history-row {{ grid-template-columns: 1fr; }}
    }}
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
      <p class="hero-sub">Alvo: {html.escape(report.target)}</p>
      <div class="hero-meta">
        <span>Gerado em: {html.escape(generated_at)}</span>
      </div>
    </header>

    <section class="context">
      <div class="context-title">Contexto</div>
      <p>Apresentamos este relatorio com uma analise da superficie de ataque da organizacao, identificando vulnerabilidades ciberneticas que podem ser exploradas por agentes maliciosos. O objetivo e avaliar riscos, priorizar correcoes e fortalecer a postura de seguranca.</p>
      <p>A superficie de ataque e o conjunto de todos os pontos de entrada potenciais que um invasor pode utilizar para comprometer sistemas, redes e aplicacoes.</p>
      <p>O objetivo deste relatorio e mapear e avaliar vulnerabilidades identificadas em ativos internos e externos, incluindo servidores, endpoints, APIs e recursos em nuvem. O escopo da analise inclui ativos corporativos expostos a internet e infraestruturas criticas internas.</p>
    </section>

    <section>
      <div class="cards">
        <div class="card"><div class="card-title">Hosts encontrados</div><div class="card-value">{total_hosts}</div></div>
        <div class="card"><div class="card-title">Portas únicas</div><div class="card-value">{total_ports}</div></div>
        <div class="card"><div class="card-title">CVEs (24h)</div><div class="card-value">{total_vulns_24h}</div></div>
      </div>
      <p class="hero-sub">Modo histórico: {"Ativado" if report.summary.history_enabled else "Desativado"}</p>
      <div class='chart-grid'>
        <div class="chart-card"><canvas id="chart-summary" aria-label="Resumo do escopo"></canvas></div>
        <div class="chart-card"><canvas id="chart-severity-global" aria-label="Severidade (24h)"></canvas></div>
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

    function renderLine(id, labels, datasets) {{
      const ctx = document.getElementById(id);
      if (!ctx) return;
      new Chart(ctx, {{
        type: 'line',
        data: {{
          labels,
          datasets: datasets.map(ds => ({{
            label: ds.label,
            data: ds.data,
            borderColor: ds.color,
            backgroundColor: ds.color + '33',
            fill: false,
            tension: 0.3,
            pointRadius: 3,
            pointHoverRadius: 4,
            borderWidth: 2,
          }})),
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          plugins: {{
            legend: {{ position: 'bottom', labels: {{ color: '#f9f5f3' }} }},
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
              ticks: {{ color: '#f9f5f3' }},
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
        if (host.trend && host.trend.labels && host.trend.labels.length) {{
          renderLine(host.trend.id, host.trend.labels, [
            {{ label: 'Portas (histórico)', data: host.trend.ports, color: colorPalette[0] }},
            {{ label: 'CVEs (histórico)', data: host.trend.cves, color: colorPalette[1] }},
          ]);
        }}
      }});
    }});
  </script>
</body>
</html>
"""
    return html_output

from __future__ import annotations

import os
import socket
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    url_for,
)

from shodan_report import (
    DEFAULT_TIMEOUT,
    collect_host_reports,
    default_output_name,
    load_api_key,
    normalize_targets,
    render_pdf_bytes,
    warning_message_text,
)

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv()
load_dotenv(PROJECT_ROOT / ".env")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY", "dev-secret-key")
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MAX_FLASH_WARNINGS = 3


def get_reports() -> list[dict[str, str]]:
    entries = []
    for pdf_path in sorted(REPORTS_DIR.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True):
        stat = pdf_path.stat()
        entries.append(
            {
                "name": pdf_path.name,
                "size_kb": f"{stat.st_size / 1024:.1f} KB",
                "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M"),
            }
        )
    return entries


def flash_warnings(warnings) -> None:
    if not warnings:
        return
    visible = warnings[:MAX_FLASH_WARNINGS]
    for warning in visible:
        flash(warning_message_text(warning), "warning")
    remaining = len(warnings) - len(visible)
    if remaining > 0:
        flash(
            f"Mais {remaining} avisos não exibidos. Consulte os logs ou reduza o escopo do alvo.",
            "warning",
        )


def parse_timeout(raw: str | None) -> int:
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        value = int(raw)
        return value if value > 0 else DEFAULT_TIMEOUT
    except ValueError:
        return DEFAULT_TIMEOUT


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template(
            "index.html",
            default_timeout=DEFAULT_TIMEOUT,
            reports=get_reports(),
        )

    raw_target = request.form.get("target", "")
    timeout = parse_timeout(request.form.get("timeout"))
    api_key_input = request.form.get("api_key") or None

    try:
        api_key = load_api_key(api_key_input)
    except RuntimeError as err:
        flash(str(err), "error")
        return redirect(url_for("index"))

    try:
        targets = normalize_targets(raw_target)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

    aggregated_reports: list = []
    aggregated_warnings: list = []
    try:
        for individual in targets:
            reports, warnings = collect_host_reports(individual, api_key, timeout)
            aggregated_reports.extend(reports)
            aggregated_warnings.extend(warnings)
    except RuntimeError as exc:
        flash(f"{individual}: {exc}", "error")
        return redirect(url_for("index"))
    except socket.gaierror as exc:
        flash(f"Não foi possível resolver {individual}: {exc}", "error")
        return redirect(url_for("index"))
    except Exception:
        flash("Não foi possível gerar o relatório. Tente novamente em instantes.", "error")
        return redirect(url_for("index"))

    flash_warnings(aggregated_warnings)

    if not aggregated_reports:
        flash("Nenhum host com dados disponíveis para gerar o relatório.", "error")
        return redirect(url_for("index"))

    target_label = ", ".join(targets)
    pdf_bytes = render_pdf_bytes(target_label, aggregated_reports)
    filename = default_output_name(targets)
    file_path = REPORTS_DIR / filename
    file_path.write_bytes(pdf_bytes)
    send_file(
        file_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
    return render_template(
            "index.html",
            default_timeout=DEFAULT_TIMEOUT,
            reports=get_reports(),
        )


@app.get("/reports/<path:filename>")
def download_report(filename: str):
    target_path = (REPORTS_DIR / filename).resolve()
    if not target_path.is_file() or REPORTS_DIR.resolve() not in target_path.parents:
        flash("Relatório não encontrado.", "error")
        return redirect(url_for("index"))
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


@app.post("/reports/<path:filename>/delete")
def delete_report(filename: str):
    target_path = (REPORTS_DIR / filename).resolve()
    if target_path.is_file() and REPORTS_DIR.resolve() in target_path.parents:
        target_path.unlink()
        flash(f"Relatório {filename} removido.", "warning")
    else:
        flash("Relatório não encontrado.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)

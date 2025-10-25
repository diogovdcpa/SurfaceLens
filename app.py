from __future__ import annotations

import os
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
    render_pdf_bytes,
    warning_message_text,
)

load_dotenv()

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

    target = request.form.get("target", "").strip()
    timeout = parse_timeout(request.form.get("timeout"))
    api_key_input = request.form.get("api_key") or None

    if not target:
        flash("Informe um IP, hostname ou domínio para gerar o relatório.", "error")
        return redirect(url_for("index"))

    try:
        api_key = load_api_key(api_key_input)
    except RuntimeError as err:
        flash(str(err), "error")
        return redirect(url_for("index"))

    try:
        host_reports, warnings = collect_host_reports(target, api_key, timeout)
    except RuntimeError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    except Exception:
        flash("Não foi possível gerar o relatório. Tente novamente em instantes.", "error")
        return redirect(url_for("index"))

    flash_warnings(warnings)

    if not host_reports:
        flash("Nenhum host com dados disponíveis para gerar o relatório.", "error")
        return redirect(url_for("index"))

    pdf_bytes = render_pdf_bytes(target, host_reports)
    filename = default_output_name(target)
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

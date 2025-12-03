from __future__ import annotations

import socket
from pathlib import Path

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    url_for,
)

from application.use_cases.report_generation import (
    DEFAULT_TIMEOUT,
    collect_host_reports,
    default_output_name,
    load_api_key,
    normalize_targets,
    render_html_report,
    render_pdf_bytes,
)
from domain.repository import ShodanRepository
from infra.controllers.web_controller import flash_warnings, get_reports, parse_timeout
from infra.repository.shodan_api_repository import ShodanAPIRepository


def build_web_blueprint(
    reports_dir: Path,
    default_api_key: str | None = None,
    repository_factory: type[ShodanRepository] = ShodanAPIRepository,
) -> Blueprint:
    """
    Cria um blueprint Flask com as rotas web.
    `default_api_key` é usada quando o usuário não informa uma chave no formulário.
    `repository_factory` permite trocar a implementação (e.g. mocks).
    """

    bp = Blueprint("web", __name__)

    @bp.get("/healthz")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @bp.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "GET":
            return render_template(
                "index.html",
                default_timeout=DEFAULT_TIMEOUT,
                reports=get_reports(reports_dir),
            )

        raw_target = request.form.get("target", "")
        company = (request.form.get("company") or "").strip()
        timeout = parse_timeout(request.form.get("timeout"))
        api_key_input = request.form.get("api_key") or None

        if not company:
            flash("Informe o nome da empresa para gerar o relatório.", "error")
            return redirect(url_for("web.index"))

        try:
            api_key = load_api_key(api_key_input, default_api_key)
        except RuntimeError as err:
            flash(str(err), "error")
            return redirect(url_for("web.index"))

        try:
            targets = normalize_targets(raw_target)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("web.index"))

        aggregated_reports: list = []
        aggregated_warnings: list = []
        repository = repository_factory(api_key)  # type: ignore[call-arg]
        try:
            for individual in targets:
                reports, warnings = collect_host_reports(individual, repository, timeout)
                aggregated_reports.extend(reports)
                aggregated_warnings.extend(warnings)
        except RuntimeError as exc:
            flash(f"{individual}: {exc}", "error")
            return redirect(url_for("web.index"))
        except socket.gaierror as exc:
            flash(f"Não foi possível resolver {individual}: {exc}", "error")
            return redirect(url_for("web.index"))
        except Exception:
            flash("Não foi possível gerar o relatório. Tente novamente em instantes.", "error")
            return redirect(url_for("web.index"))

        flash_warnings(aggregated_warnings)

        if not aggregated_reports:
            flash("Nenhum host com dados disponíveis para gerar o relatório.", "error")
            return redirect(url_for("web.index"))

        target_label = ", ".join(targets)
        pdf_bytes = render_pdf_bytes(target_label, aggregated_reports, company=company)
        html_content = render_html_report(target_label, aggregated_reports, company=company)
        pdf_filename = default_output_name(targets)
        base_name = pdf_filename.rsplit(".", 1)[0]
        html_filename = f"{base_name}.html"
        file_path_pdf = reports_dir / pdf_filename
        file_path_html = reports_dir / html_filename
        file_path_pdf.write_bytes(pdf_bytes)
        file_path_html.write_text(html_content, encoding="utf-8")

        flash("Relatórios gerados com sucesso (PDF e HTML).", "success")
        return redirect(url_for("web.index"))

    @bp.get("/reports/<path:filename>")
    def download_report(filename: str):
        target_path = (reports_dir / filename).resolve()
        reports_root = reports_dir.resolve()
        if not target_path.is_file() or reports_root not in target_path.parents:
            flash("Relatório não encontrado.", "error")
            return redirect(url_for("web.index"))
        return send_from_directory(reports_dir, filename, as_attachment=True)

    @bp.post("/reports/<path:basename>/delete")
    def delete_report_set(basename: str):
        reports_root = reports_dir.resolve()
        removed = False
        for ext in (".pdf", ".html"):
            target_path = (reports_dir / f"{basename}{ext}").resolve()
            if target_path.is_file() and reports_root in target_path.parents:
                target_path.unlink()
                removed = True
        if removed:
            flash(f"Conjunto {basename} removido.", "warning")
        else:
            flash("Relatório não encontrado.", "error")
        return redirect(url_for("web.index"))

    return bp

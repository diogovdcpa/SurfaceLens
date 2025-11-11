from __future__ import annotations

import argparse
import socket
from pathlib import Path

from dotenv import load_dotenv

from shodan_report import (
    DEFAULT_TIMEOUT,
    collect_host_reports,
    default_output_name,
    load_api_key,
    normalize_targets,
    render_pdf_bytes,
    warning_message_text,
)


def load_environment() -> None:
    project_env = Path(__file__).resolve().parent / ".env"
    load_dotenv()
    load_dotenv(project_env)  # Garantir carregamento mesmo fora do diretório do projeto


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Consulta a API do Shodan para um alvo (IP, hostname ou domínio) "
            "e gera um relatório em PDF."
        )
    )
    parser.add_argument("target", help="IP/hostname/FQDN/domínio aceito pelo Shodan")
    parser.add_argument(
        "-o",
        "--output",
        help="Caminho do arquivo PDF de saída (padrão: relatorio-<alvo>-<data>.pdf)",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        help="Chave da API do Shodan (padrão: variável de ambiente SHODAN_API_KEY)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout das requisições em segundos (padrão: {DEFAULT_TIMEOUT})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    load_environment()
    try:
        api_key = load_api_key(args.api_key)
    except RuntimeError as err:
        raise SystemExit(f"Erro: {err}") from err

    try:
        targets = normalize_targets(args.target)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    aggregated_reports = []
    aggregated_warnings = []
    for individual in targets:
        try:
            reports, warnings = collect_host_reports(individual, api_key, args.timeout)
        except socket.gaierror as exc:
            raise SystemExit(f"Não foi possível resolver {individual}: {exc}") from exc
        except RuntimeError as exc:
            raise SystemExit(f"{individual}: {exc}") from exc
        aggregated_reports.extend(reports)
        aggregated_warnings.extend(warnings)

    for warning in aggregated_warnings:
        print(f"Aviso: {warning_message_text(warning, verbose=True)}")

    if not aggregated_reports:
        raise SystemExit("Nenhum host com dados disponíveis para gerar o relatório.")

    target_label = ", ".join(targets)
    output_path = Path(args.output or default_output_name(targets))
    pdf_bytes = render_pdf_bytes(target_label, aggregated_reports)
    output_path.write_bytes(pdf_bytes)
    print(f"Relatório salvo em {output_path}")


if __name__ == "__main__":
    main()

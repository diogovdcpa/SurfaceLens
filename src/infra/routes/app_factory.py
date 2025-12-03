from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask

from infra.repository.shodan_api_repository import ShodanAPIRepository
from infra.routes.web_routes import build_web_blueprint

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = PROJECT_ROOT / "src"


def create_app() -> Flask:
    """
    Cria e configura a aplicação Flask.
    - Carrega variáveis do .env na raiz do projeto.
    - Configura diretórios de static/templates na raiz.
    - Registra o blueprint web com o repositório do Shodan.
    """
    load_dotenv()
    load_dotenv(PROJECT_ROOT / ".env")

    app = Flask(
        __name__,
        static_folder=str(SRC_ROOT / "static"),
        template_folder=str(SRC_ROOT / "templates"),
    )
    app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY", "dev-secret-key")

    reports_env = os.getenv("REPORTS_DIR")
    reports_dir = Path(reports_env) if reports_env else SRC_ROOT / "reports"
    if not reports_dir.is_absolute():
        reports_dir = (SRC_ROOT / reports_dir).resolve()
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Ambiente somente leitura (ex: serverless). Usa /tmp como fallback.
        reports_dir = Path("/tmp/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

    default_api_key = os.getenv("SHODAN_API_KEY")
    # Histórico ligado por padrão; defina USE_SHODAN_HISTORY=false para desativar
    env_history = os.getenv("USE_SHODAN_HISTORY")
    use_history = True if env_history is None else env_history.lower() == "true"
    web_bp = build_web_blueprint(
        reports_dir=reports_dir,
        default_api_key=default_api_key,
        repository_factory=ShodanAPIRepository,
        use_history=use_history,
    )
    app.register_blueprint(web_bp)
    return app


__all__ = ["create_app"]

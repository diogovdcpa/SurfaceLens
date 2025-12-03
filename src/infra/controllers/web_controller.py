from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from flask import flash

from application.use_cases.report_generation import DEFAULT_TIMEOUT, warning_message_text

MAX_FLASH_WARNINGS = 3


def get_reports(reports_dir: Path) -> list[dict[str, Any]]:
    """
    Retorna os relatórios disponíveis agrupados por base (pdf/html).
    """
    entries: dict[str, dict[str, Any]] = {}

    def register(path: Path, kind: str) -> None:
        stat = path.stat()
        base = path.stem
        entry = entries.setdefault(
            base,
            {
                "base": base,
                "mtime": stat.st_mtime,
                "mtime_str": datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M"),
                "pdf": None,
                "html": None,
            },
        )
        if stat.st_mtime > entry["mtime"]:
            entry["mtime"] = stat.st_mtime
            entry["mtime_str"] = datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M")
        entry[kind] = {"name": path.name, "size_kb": f"{stat.st_size / 1024:.1f} KB"}

    for pattern, kind in (("*.pdf", "pdf"), ("*.html", "html")):
        for path in reports_dir.glob(pattern):
            register(path, kind)

    return sorted(entries.values(), key=lambda item: item["mtime"], reverse=True)


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

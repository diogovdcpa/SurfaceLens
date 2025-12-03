from __future__ import annotations

from datetime import datetime
from pathlib import Path

from flask import flash

from application.use_cases.report_generation import DEFAULT_TIMEOUT, warning_message_text

MAX_FLASH_WARNINGS = 3


def get_reports(reports_dir: Path) -> list[dict[str, str]]:
    entries = []
    for pdf_path in sorted(reports_dir.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True):
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

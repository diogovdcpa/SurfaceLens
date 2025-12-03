from __future__ import annotations

from dataclasses import dataclass
from typing import List

from domain.entity import HostReport, ReportWarning


@dataclass
class ReportRequestDTO:
    targets: List[str]
    timeout: int


@dataclass
class ReportResultDTO:
    hosts: List[HostReport]
    warnings: List[ReportWarning]
    filename: str
    pdf_bytes: bytes

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

from domain.entity import HostReport, VulnerabilityDetail


@dataclass
class ReportHost:
    host: HostReport
    all_vulns: List[VulnerabilityDetail]
    severity_counts: Dict[str, int]
    unique_ports: int


@dataclass
class ReportSummary:
    total_hosts: int
    total_ports: int
    total_vulns: int
    severity_global: Dict[str, int]
    history_enabled: bool


@dataclass
class ReportModel:
    target: str
    company: str
    generated_at: datetime
    hosts: List[ReportHost]
    summary: ReportSummary

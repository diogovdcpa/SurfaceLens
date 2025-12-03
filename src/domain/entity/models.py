from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class VulnerabilityDetail:
    cve: str
    cvss: float | str | None = None
    verified: bool | None = None
    references: List[str] = field(default_factory=list)


@dataclass
class ServiceInfo:
    port: int
    transport: str
    product: str | None
    version: str | None
    cpe: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    vulns: List[VulnerabilityDetail] = field(default_factory=list)
    info: str | None = None


@dataclass
class HostReport:
    ip: str
    hostnames: List[str]
    org: str | None
    isp: str | None
    os: str | None
    location: str | None
    open_ports: List[int]
    tags: List[str]
    vulns: List[VulnerabilityDetail]
    services: List[ServiceInfo]


@dataclass
class ReportWarning:
    ip: str
    kind: str
    detail: str | None = None

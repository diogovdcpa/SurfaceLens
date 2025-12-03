from __future__ import annotations

from typing import Protocol

from domain.entity import HostReport


class ShodanRepository(Protocol):
    """
    Contrato para fontes de dados do Shodan.
    Implementações podem usar API HTTP, mocks ou caches locais.
    """

    def fetch_host_report(self, ip: str, timeout: int, include_history: bool = False) -> HostReport:
        ...

    def fetch_domain_history(self, domain: str, timeout: int) -> tuple[list[str], str | None]:
        """
        Retorna (ips, erro). O erro é uma string amigável para exibição.
        """
        ...

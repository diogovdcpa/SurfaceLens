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

    def fetch_dns_resolve(self, domain: str, timeout: int) -> tuple[list[str], str | None]:
        """
        Resolve o domínio via endpoint /dns/resolve do Shodan.
        Retorna (ips, erro). O erro é uma string amigável para exibição.
        """
        ...

    def fetch_host_search(
        self,
        domain: str,
        timeout: int,
        limit: int | None = None,
    ) -> tuple[list[str], str | None]:
        """
        Busca hosts no Shodan via /shodan/host/search usando hostname/domain.
        Retorna (ips, erro). O erro é uma string amigável para exibição.
        """
        ...

# Spec - Correcao de busca por dominio sem retorno

## Problema
- Dominios validos podem retornar lista vazia de hosts ou erro silencioso devido a
  falhas de resolucao (A/AAAA) e/ou ausencia de dados do Shodan para os IPs
  resolvidos.

## Objetivos
- Garantir retorno quando existirem dados no Shodan.
- Tornar a resolucao de alvos mais resiliente (DNS local + Shodan).
- Gerar relatorio agregado a partir de lista de IOCs (IP/hostname/dominio/CIDR).
- Exibir mensagens claras quando nao houver dados.

## Fora de escopo
- Redesenho de UI/relatorios.
- Trocar provedor Shodan.

## Fluxo atual (validado no codebase)
1) `normalize_targets` separa IOCs por virgula.
2) `resolve_target`:
   - CIDR -> lista de IPs (erro se exceder `MAX_TARGET_IPS`).
   - IP -> retorna.
   - Dominio/hostname -> `resolve_domain_target`.
3) `resolve_domain_target`:
   - DNS local via `socket.getaddrinfo` (A/AAAA).
   - Se falhar, fallback via Shodan `/dns/resolve`.
   - Historico passivo via `/dns/domain/{domain}` (filtra A/AAAA).
   - Combina IPs, deduplica e aplica limite `MAX_TARGET_IPS`.
4) Para cada IP final: `/shodan/host/{ip}` (com `history=true` se `USE_SHODAN_HISTORY`).
5) Se nenhum host retornar dados e nao houve erro de rede/rate limit:
   warning `no_shodan_data`.

## Gaps / pontos a decidir
- Confirmar se `/dns/domain/{domain}` aceita `history=true` (nao documentado em
  `project/api.md`) e ajustar a chamada se necessario.
- Avaliar fallback opcional via `/shodan/host/search` (`hostname:`/`domain:`) para
  dominios que nao retornam IPs por DNS.
- Revisar mensagens para garantir que a UI diferencie falha de DNS local vs Shodan.

## Requisitos funcionais
- Entrada aceita lista de IOCs (IP/hostname/dominio/CIDR) separados por virgula.
- Para dominios/hostnames:
  - Resolver DNS local (A/AAAA); se falhar, usar `/dns/resolve`.
  - Consultar `/dns/domain/{domain}` e combinar com DNS local.
  - Deduplicar IPs e aplicar `MAX_TARGET_IPS`.
- Para cada IP final: consultar `/shodan/host/{ip}` com `history=true` quando ativo.
- Quando nenhum IP gerar dados:
  - Informar se foi "sem dados no Shodan" ou "falha de resolucao".
- Gerar relatorio PDF/HTML agregado com todos os IOCs enviados.

## Requisitos nao funcionais
- Minimizar chamadas extras ao Shodan (respeitar rate limit e creditos).
- Reusar `DEFAULT_TIMEOUT`.
- Nao expor API key em logs/UI.

## Mudancas planejadas (se aprovadas)
- `src/infra/repository/shodan_api_repository.py`:
  - Ajustar `fetch_domain_history` se `history=true` nao for suportado.
- `src/domain/repository/shodan_repository.py` e
  `src/application/use_cases/report_generation.py`:
  - Adicionar contrato e fallback opcional via `/shodan/host/search`.
- `src/application/report_utils.py` e `src/infra/routes/web_routes.py`:
  - Validar mensagens de warning para casos de resolucao vs ausencia de dados.

## Mensagens esperadas (UI)
- "Nenhum dado encontrado no Shodan para os IPs resolvidos."
- "Falha ao resolver DNS local; tentando Shodan."
- "Falha ao resolver DNS via Shodan."
- "Limite de IPs atingido (MAX_TARGET_IPS); resultados podem ser parciais."

## Criterios de aceitacao
- Dominio com dados retorna relatorio com >= 1 host.
- Dominio sem dados retorna warning claro, sem falha silenciosa.
- Lista de IOCs gera relatorio agregado (com nome de arquivo coerente).
- Erros de resolucao informam causa provavel (DNS local vs Shodan).

## Testes sugeridos
- Unit: `resolve_domain_target` com DNS local falho + fallback `/dns/resolve`.
- Unit: combinacao/deduplicacao + limite `MAX_TARGET_IPS`.
- Unit: `normalize_targets` com lista de IOCs.
- Integracao: dominio com dados reais (mock Shodan) e multiplos IOCs.

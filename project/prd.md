# PRD: Corrigir busca por dominio sem retorno (ex: sapore.com.br)

## Nota sobre referencias
- Sem acesso a internet neste ambiente; validacao feita com `project/api.md`,
  `project/shodan.json` e o codebase atual. Qualquer ponto marcado como
  "a confirmar" precisa de verificacao externa (ex: GitHub/docs oficiais).

## Contexto
- A aplicacao consulta a API do Shodan a partir de IOCs (IP/hostname/dominio/CIDR)
  informados no formulario.
- Suporta multiplos alvos separados por virgula e gera PDF/HTML agregados.
- Problema reportado: ao inserir `sapore.com.br`, nao retorna nenhum resultado.

## Problema
- O fluxo de resolucao/coleta de dados pode retornar lista vazia para dominios
  especificos, mesmo quando existem dados no Shodan.

## Objetivos
- Garantir que dominios validos retornem dados quando existirem no Shodan.
- Melhorar a resiliencia da resolucao de alvos (DNS local + Shodan).
- Permitir gerar relatorio com base em lista de IOCs (agregado) de forma confiavel.
- Expor erros/avisos de forma clara no UI quando nao houver dados.

## Nao objetivos
- Reescrever a interface web ou o layout do relatorio.
- Substituir a API do Shodan por outro provedor.

## Fluxo atual (validado no codebase)
- `normalize_targets` divide a entrada em alvos (IOCs) separados por virgula.
- `resolve_target`:
  - CIDR -> lista de IPs (erro se exceder `MAX_TARGET_IPS`).
  - IP -> retorna.
  - Dominio/hostname -> `resolve_domain_target`.
- `resolve_domain_target`:
  - DNS local via `socket.getaddrinfo` (A/AAAA).
  - Se falhar, fallback via Shodan `/dns/resolve`.
  - Busca historico passivo via Shodan `/dns/domain/{domain}` e filtra A/AAAA.
  - Combina e remove duplicados; aplica limite `MAX_TARGET_IPS`.
- Para cada IP final: `fetch_host_report` chama `/shodan/host/{ip}` (com
  `history=true` quando `USE_SHODAN_HISTORY`).
- Se nenhum host retornar dados e nao houve erros de rede/rate limit, gera warning
  `no_shodan_data`.

## Validacao de chamadas a API Shodan (codebase vs api.md)
- `/shodan/host/{ip}`: usado em `fetch_host_report` com `key` e `history=true`
  opcional.
- `/dns/domain/{domain}`: usado em `fetch_domain_history` com `key` e
  `history=true` (parametro nao documentado em `project/api.md`; confirmar se e
  suportado ou remover).
- `/dns/resolve`: usado em `fetch_dns_resolve` com `key` e `hostnames=<dominio>`.
- `404` em `/shodan/host/{ip}` gera `ShodanNotFoundError`; `404` em
  `/dns/domain/{domain}` e tratado como "sem historico".
- Endpoints `/shodan/host/search` e `/shodan/host/count` nao sao usados hoje
  (sem fallback via busca por hostname/domain).

## Hipoteses para o problema (priorizadas)
1) DNS local e `/dns/resolve` falham ou nao retornam A/AAAA para o dominio.
2) `/dns/domain` nao retorna registros A/AAAA relevantes (ou o parametro
   `history` e ignorado).
3) IPs resolvidos estao atras de CDN/proxy e nao possuem dados no Shodan.
4) Limite `MAX_TARGET_IPS` corta IPs relevantes, resultando em amostra sem dados.

## Solucoes candidatas
- Confirmar se `/dns/domain` aceita `history=true` e ajustar o request se necessario.
- Adicionar fallback opcional via `/shodan/host/search` (query `hostname:`/`domain:`)
  para evitar relatorio vazio quando DNS falhar.
- Melhorar mensagens de warning para diferenciar "sem dados no Shodan" vs
  "falha de resolucao".
- Permitir rotular/organizar relatorio por IOC quando multiplos alvos forem enviados.

## Requisitos funcionais
- Entrada aceita uma lista de IOCs (IP/hostname/dominio/CIDR) separados por virgula.
- Para dominios/hostnames:
  - Tentar DNS local (A/AAAA); se falhar, usar `/dns/resolve`.
  - Consultar `/dns/domain/{domain}` e combinar com DNS local.
  - Remover duplicados e aplicar `MAX_TARGET_IPS`.
- Para cada IP final: consultar `/shodan/host/{ip}` com `history=true` quando
  habilitado.
- Quando nenhum IP gerar dados:
  - Informar se foi "sem dados no Shodan" ou "falha de resolucao".
- Gerar relatorio PDF/HTML unico com o agregado de todos os IOCs.

## Requisitos nao funcionais
- Minimizar chamadas extras ao Shodan (respeitar rate limit e creditos).
- Manter `timeout` configuravel (`DEFAULT_TIMEOUT`).
- Nao expor a API key em logs/UI.

## Criterios de aceitacao
- Dominio com dados no Shodan gera relatorio com ao menos 1 host.
- Dominio sem dados gera warning claro sem falha silenciosa.
- Lista de IOCs gera relatorio agregado (com nome de arquivo coerente).
- Mensagens distinguem falha de DNS local, falha de Shodan DNS e ausencia de dados.

## Testes sugeridos
- Unit: `resolve_domain_target` com DNS local falho + fallback `/dns/resolve`.
- Unit: combinacao de IPs e limite `MAX_TARGET_IPS`.
- Unit: `normalize_targets` com lista de IOCs.
- Integracao: dominio com dados reais (mock do Shodan) e multiplos IOCs.

## Arquivos relevantes
- `src/application/use_cases/report_generation.py` (resolucao e normalizacao de alvos)
- `src/domain/repository/shodan_repository.py` (contratos)
- `src/infra/repository/shodan_api_repository.py` (endpoints Shodan)
- `src/infra/routes/web_routes.py` (entrada de alvos e warnings)
- `src/application/report_utils.py` (mensagens de warning)

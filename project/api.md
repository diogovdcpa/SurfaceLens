# API Shodan - Estrutura para SurfaceLens

## Objetivo
Documentar a API do Shodan usada pela aplicacao, com base no `project/shodan.json`, em um formato direto para implementacao e manutencao.

## Base URL e autenticacao
Base URL: `https://api.shodan.io`
Autenticacao: query param `key` (obrigatorio em todos os endpoints).

## Convencoes gerais
Formato: JSON em respostas.
Erros: normalmente retornam `{ "error": "mensagem" }` com HTTP 4xx/5xx (ex: 404 "Invalid IP").
Paginacao: `page` em buscas (100 resultados por pagina).
Facets: `facets` aceita lista separada por virgula (ex: `org,os`).
Historico: `history=true` retorna banners historicos em `/shodan/host/{ip}`.
Minify: `minify=true` retorna apenas portas e dados gerais do host.

## Modelos de resposta (resumo)
HostInfo: `ip_str`, `ports[]`, `hostnames[]`, `org`, `isp`, `asn`, `tags[]`, `location{}`, `data[]`.
SearchResults: `matches[]`, `total`, `facets{}`.
DNSDomain: `domain`, `tags[]`, `subdomains[]`, `data[]`, `more`.
DNSResolve: mapa `{ hostname: ip }`.
DNSReverse: mapa `{ ip: [hostnames] }`.
ApiInfo: `plan`, `query_credits`, `scan_credits`, `usage_limits{}`.
AccountProfile: `member`, `credits`, `created`, `display_name`.
Alert: `id`, `name`, `filters`, `triggers`, `created`, `expiration`, `size`.
Notifier: `id`, `provider`, `description`, `args`.
ScanStatus: `id`, `status`, `count`, `created`.

## Search Methods
### GET /shodan/host/{ip} - Host Information
Parametros: `ip` (path, obrigatorio), `history` (query), `minify` (query).
Resposta: detalhes do host e banners por servico.

### GET /shodan/host/search - Search Shodan
Parametros: `query` (query, obrigatorio), `facets` (query), `page` (query).
Resposta: `matches[]`, `total`, `facets{}`.

### GET /shodan/host/count - Search Shodan without Results
Parametros: `query` (query, obrigatorio), `facets` (query).
Resposta: total e facets sem resultados completos.

### GET /shodan/host/search/facets - List all search facets
Parametros: nenhum alem de `key`.

### GET /shodan/host/search/filters - List all filters that can be used when searching
Parametros: nenhum alem de `key`.

### GET /shodan/host/search/tokens - Break the search query into tokens
Parametros: `query` (query, obrigatorio).

## DNS Methods
### GET /dns/domain/{domain} - Domain Information
Parametros: `domain` (path, obrigatorio).
Resposta: subdominios e registros DNS observados pelo Shodan.

### GET /dns/resolve - DNS Lookup
Parametros: `hostnames` (query, ex: `a.com,b.com`).
Resposta: mapa hostname -> IP.

### GET /dns/reverse - Reverse DNS Lookup
Parametros: `ips` (query, ex: `8.8.8.8,1.1.1.1`).
Resposta: mapa IP -> lista de hostnames.

## On-Demand Scanning
### POST /shodan/scan - Request Shodan to crawl an IP/ netblock
Body: `application/x-www-form-urlencoded` com `ips` (lista de IPs ou CIDR).

### POST /shodan/scan/internet - Crawl the Internet for a specific port/protocol
Body: `application/x-www-form-urlencoded` com `port` (int) e `protocol` (string).

### GET /shodan/scans - Get list of all the created scans
Resposta: `matches[]`, `total`.

### GET /shodan/scans/{id} - Get the status of a scan request
Parametros: `id` (path, obrigatorio).
Resposta: `id`, `status`, `count`, `created`.

### GET /shodan/ports - List all ports that Shodan is crawling on the Internet
Parametros: nenhum alem de `key`.

### GET /shodan/protocols - List all protocols usable in on-demand scans
Parametros: nenhum alem de `key`.

## Network Alerts
### POST /shodan/alert - Create an alert to monitor a network range
Body: `application/json` com `name`, `filters` (ex: `{ "ip": ["8.8.8.8"] }`), `expires` (opcional).

### GET /shodan/alert/info - Get a list of all the created alerts
Resposta: lista de alertas.

### GET /shodan/alert/{id}/info - Get the details for a network alert
Parametros: `id` (path, obrigatorio).
Resposta: detalhes do alerta, `notifiers` e `triggers`.

### POST /shodan/alert/{id} - Edit the networks monitored in an alert
Parametros: `id` (path, obrigatorio).
Body: `application/json` com `filters`.

### DELETE /shodan/alert/{id} - Delete an alert
Parametros: `id` (path, obrigatorio).

### GET /shodan/alert/triggers - Get a list of available triggers
Resposta: lista de triggers.

### PUT /shodan/alert/{id}/trigger/{trigger} - Enable a trigger
Parametros: `id` (path), `trigger` (path).

### DELETE /shodan/alert/{id}/trigger/{trigger} - Disable a trigger
Parametros: `id` (path), `trigger` (path).

### PUT /shodan/alert/{id}/trigger/{trigger}/ignore/{service} - Add to Whitelist
Parametros: `id` (path), `trigger` (path), `service` (path).

### DELETE /shodan/alert/{id}/trigger/{trigger}/ignore/{service} - Remove from Whitelist
Parametros: `id` (path), `trigger` (path), `service` (path).

### PUT /shodan/alert/{id}/notifier/{notifier_id} - Add the notifier to the alert
Parametros: `id` (path), `notifier_id` (path).

### DELETE /shodan/alert/{id}/notifier/{notifier_id} - Remove the notifier from the alert
Parametros: `id` (path), `notifier_id` (path).

## Notifiers
### GET /notifier - List all user-created notifiers
Resposta: `matches[]`, `total`.

### POST /notifier - Create a new notification service for the user
Body: `application/x-www-form-urlencoded` com `provider`, `description`, `to`.

### GET /notifier/provider - List of available notification providers
Resposta: mapa com provedores e seus parametros.

### GET /notifier/{id} - Get information about a notifier
Parametros: `id` (path, obrigatorio).

### PUT /notifier/{id} - Edit a notifier
Parametros: `id` (path, obrigatorio).
Body: `application/x-www-form-urlencoded` com `to`.

### DELETE /notifier/{id} - Delete a notification service
Parametros: `id` (path, obrigatorio).

## Directory Methods
### GET /shodan/query - List the saved search queries
Resposta: lista de queries salvas.

### GET /shodan/query/search - Search the directory of saved search queries
Parametros: `query` (query, obrigatorio).

### GET /shodan/query/tags - List the most popular tags
Resposta: lista de tags.

## Bulk Data (Enterprise)
### GET /shodan/data - Get a list of available datasets
Resposta: lista com `name`, `scope`, `description`.

### GET /shodan/data/{dataset} - List the files for a dataset
Parametros: `dataset` (path, obrigatorio).
Resposta: lista com `url`, `timestamp`, `sha1`, `name`, `size`.

## Manage Organization (Enterprise)
### GET /org - General Information
Resposta: dados da organizacao, membros e dominios autorizados.

### PUT /org/member/{user} - Add a new member
Parametros: `user` (path, obrigatorio), `notify` (query).

### DELETE /org/member/{user} - Remove a member
Parametros: `user` (path, obrigatorio).

## Account Methods
### GET /account/profile - Account Methods
Resposta: dados da conta vinculada ao `key`.

## API Status Methods
### GET /api-info - API Plan Information
Resposta: plano, creditos e limites.

## Utility Methods
### GET /tools/httpheaders - HTTP Headers
Resposta: headers que seu cliente envia.

### GET /tools/myip - My IP Address
Resposta: IP publico visto pelo Shodan.

## Uso sugerido na aplicacao
Consulta de host: `/shodan/host/{ip}` (com `history` opcional).
Resolucao de dominios: `/dns/resolve` e `/dns/domain/{domain}`.
Fallback de busca: `/shodan/host/search` ou `/shodan/host/count` para evitar relatorios vazios.
Limites e plano: `/api-info`.


# SurfaceLens

SurfaceLens é uma aplicação web que consulta a API do Shodan a partir de um IP, hostname, domínio ou bloco CIDR e gera automaticamente um relatório em PDF com os serviços expostos pelo alvo. O ponto de entrada Flask fica em `main.py` (expondo `create_app`).

## Estrutura (DDD simplificado)

```
src/
  application/
    dtos/                 # Objetos de transporte (pedido/resultado de relatório)
    use_cases/            # Caso de uso de geração do relatório e PDF
  domain/
    entity/               # Entidades: HostReport, ServiceInfo, VulnerabilityDetail, ReportWarning
    repository/           # Contratos de repositório (ShodanRepository)
  infra/
    controllers/          # Auxiliares de controller (flash, parse, listagem de PDFs)
    repository/           # Implementação do repositório Shodan via API HTTP
    routes/               # Blueprint e fábrica do Flask (`create_app`)
  static/                 # Assets estáticos do front
  templates/              # Templates HTML do Flask
  reports/                # Saída padrão dos PDFs gerados
```

Pontos de extensão rápidos:
- PDF e regras do caso de uso: `src/application/use_cases/report_generation.py`.
- Contrato do Shodan: `src/domain/repository/shodan_repository.py`.
- Implementação da API do Shodan: `src/infra/repository/shodan_api_repository.py` (troque aqui se quiser mock/cache).
- Rotas web/blueprint: `src/infra/routes/web_routes.py`.

## Pré-requisitos

- Python 3.11 ou superior.
- Dependências listadas no `pyproject.toml`. Recomenda-se um ambiente virtual:
  ```bash
  python -m venv .venv
  source .venv/bin/activate  # (Linux/macOS)  |  .venv\Scripts\activate (Windows)
  pip install "requests>=2.32.3" "fpdf2>=2.7.9" "python-dotenv>=1.0.1" "flask>=3.1.2" "matplotlib>=3.9.2"
  # ou use o uv:  uv pip install -r pyproject.toml
  ```
- Uma chave válida da API do [Shodan](https://www.shodan.io/). Defina `SHODAN_API_KEY` em um `.env` na raiz do projeto ou exporte a variável no shell.

### Variáveis de ambiente

- `SHODAN_API_KEY` **(obrigatória)** – chave da API.
- `APP_SECRET_KEY` – chave de sessão para o Flask; padrão `dev-secret-key`.
- `REPORTS_DIR` – diretório onde os PDFs gerados pela interface web são armazenados; padrão `src/reports/` (relativo à pasta `src`).

## Como usar (web)

1. Instale as dependências (veja acima).
2. Garanta que o `.env` contenha `SHODAN_API_KEY=<sua_chave>` ou exporte `SHODAN_API_KEY` para o ambiente.
3. Inicie o servidor:
   ```bash
   flask --app main run --reload
   # ou
   python main.py
   ```
4. Acesse `http://127.0.0.1:5000`, informe o alvo (IP/hostname/domínio/bloco) e aguarde o download automático do PDF.

O endpoint `/healthz` retorna o status da aplicação para monitoramento simples.

## Relatório gerado

O PDF inclui:

- Resumo do alvo solicitado e data/hora da coleta.
- Para cada IP retornado pelo Shodan: hostnames, organização, ISP, sistema operacional, localização, tags e portas abertas.
- Listagem detalhada dos serviços expostos, com produto, versão, CPEs, tags e vulnerabilidades reportadas pela API.

Os arquivos são salvos no diretório configurado em `REPORTS_DIR`.

## Dicas

- Se o alvo for um domínio, a aplicação combina os IPs resolvidos via DNS com o histórico passivo do Shodan (`/dns/domain`) e gera uma seção para cada endereço encontrado.
- Caso o IP não possua dados públicos no Shodan, um aviso é exibido e ele é ignorado no relatório.
- Adapte o relatório conforme necessário (por exemplo, adicionando gráficos ou traduzindo campos) estendendo o código em `src/`.

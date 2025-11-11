# SurfaceLens

SurfaceLens é uma aplicação de linha de comando e web que consulta a API do Shodan a partir de um IP, hostname, domínio ou bloco CIDR e gera automaticamente um relatório em PDF com os serviços expostos pelo alvo.

## Pré-requisitos

- Python 3.11 ou superior.
- Dependências listadas no `pyproject.toml`. Recomenda-se um ambiente virtual:
  ```bash
  python -m venv .venv
  source .venv/bin/activate  # (Linux/macOS)  |  .venv\Scripts\activate (Windows)
  pip install "requests>=2.32.3" "fpdf2>=2.7.9" "python-dotenv>=1.0.1" "flask>=3.1.2" "matplotlib>=3.9.2"
  # ou use o uv:  uv pip install -r pyproject.toml
  ```
- Uma chave válida da API do [Shodan](https://www.shodan.io/). Defina `SHODAN_API_KEY` em um `.env` na raiz do projeto (carregado automaticamente tanto pelo CLI quanto pelo servidor web), exporte a variável no shell ou informe via `--api-key`.

### Variáveis de ambiente suportadas

- `SHODAN_API_KEY` **(obrigatória)** – chave da API.
- `APP_SECRET_KEY` – chave de sessão para o Flask; padrão `dev-secret-key`.
- `REPORTS_DIR` – diretório onde os PDFs gerados pela interface web são armazenados; padrão `reports/`.

## Como usar (CLI)

1. Instale as dependências:
   ```bash
   # com o ambiente virtual ativado
   pip install "requests>=2.32.3" "fpdf2>=2.7.9" "python-dotenv>=1.0.1" "flask>=3.1.2" "matplotlib>=3.9.2"
   ```
2. Garanta que o `.env` contenha `SHODAN_API_KEY=<sua_chave>` ou exporte `SHODAN_API_KEY` para o ambiente.
3. Execute informando o alvo desejado (a aplicação carrega automaticamente o `.env` a partir da raiz do projeto, mesmo que você execute o comando fora dela):
   ```bash
   python main.py 8.8.8.8
   ```

### Opções principais

```bash
usage: main.py [-h] [-o OUTPUT] [--api-key API_KEY] [--timeout TIMEOUT] target
```

- `target`: IP, hostname, FQDN, domínio ou bloco CIDR (ex: `177.10.40.0/22`, limitado a 1024 IPs por execução).
- `-o/--output`: caminho do PDF gerado. Se omitido, o arquivo recebe o padrão `relatorio-shodan-<alvo>-<data>.pdf`.
- `--api-key`: chave da API do Shodan (caso não tenha configurado `SHODAN_API_KEY`).
- `--timeout`: timeout das requisições, em segundos (padrão 20s).

## Funcionamento via Web

Também é possível executar a aplicação como um servidor Flask:

1. Defina `SHODAN_API_KEY` e, opcionalmente, `APP_SECRET_KEY` para os flashes.
   > O arquivo `.env` da raiz é carregado automaticamente durante o `flask run`, então basta manter as variáveis definidas nele.
2. Inicie o servidor (a partir de qualquer diretório, desde que o projeto esteja no `PYTHONPATH`/virtualenv ativo):
   ```bash
   flask --app app run --reload
   ```
3. Acesse `http://127.0.0.1:5000` e informe o alvo pelo formulário. O relatório será baixado automaticamente após a geração.

O endpoint `/healthz` retorna o status da aplicação para monitoramento simples.

## Relatório gerado

O PDF inclui:

- Resumo do alvo solicitado e data/hora da coleta.
- Para cada IP retornado pelo Shodan: hostnames, organização, ISP, sistema operacional, localização, tags e portas abertas.
- Listagem detalhada dos serviços expostos, com produto, versão, CPEs, tags e vulnerabilidades reportadas pela API.

O arquivo é salvo no diretório atual (ou no caminho especificado em `-o`).

## Dicas

- Se o alvo for um domínio, a aplicação combina os IPs resolvidos via DNS com o histórico passivo do Shodan (`/dns/domain`) e gera uma seção para cada endereço encontrado.
- Caso o IP não possua dados públicos no Shodan, um aviso é exibido e ele é ignorado no relatório.
- Adapte o relatório conforme necessário (por exemplo, adicionando gráficos ou traduzindo campos) estendendo o código em `main.py`.

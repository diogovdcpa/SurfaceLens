# SurfaceLens

SurfaceLens é uma aplicação de linha de comando e web que consulta a API do Shodan a partir de um IP, hostname, domínio ou bloco CIDR e gera automaticamente um relatório em PDF com os serviços expostos pelo alvo.

## Pré-requisitos

- Python 3.11 ou superior.
- Dependências listadas no `pyproject.toml` (instale com `uv pip install -r pyproject.toml` ou `pip install -e .`).
- Uma chave válida da API do [Shodan](https://www.shodan.io/). Defina-a na variável de ambiente `SHODAN_API_KEY`, coloque-a em um arquivo `.env` (carregado automaticamente) ou informe via `--api-key` ao executar.

## Como usar (CLI)

1. Instale as dependências:
   ```bash
   pip install -e .
   ```
2. Execute informando o alvo desejado:
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
2. Inicie o servidor:
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

- Se o alvo for um domínio, a aplicação resolve para todos os IPs disponíveis e gera uma seção para cada um.
- Caso o IP não possua dados públicos no Shodan, um aviso é exibido e ele é ignorado no relatório.
- Adapte o relatório conforme necessário (por exemplo, adicionando gráficos ou traduzindo campos) estendendo o código em `main.py`.

# Projeto Valsec

Aplicação web simples em Go para testar técnicas de balanceamento do Cloudflare.

## Descrição

Este projeto consiste em uma aplicação web em Go que exibe diferentes cores dependendo da versão:
- **Versão A**: Tela rosa
- **Versão B**: Tela azul

A versão é controlada pela variável de ambiente `VERSION`.

## Estrutura do Projeto

```
├── valsec/
│   ├── main.go         # Código fonte da aplicação Go
│   ├── Dockerfile      # Dockerfile para construir a imagem
│   └── chart/          # Helm chart para implantação
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── deployment-a.yaml
│           ├── deployment-b.yaml
│           ├── service.yaml
│           └── ingress.yaml
```

## Como Usar

### Construir a Imagem Docker

```bash
cd app
docker build -t valsec:latest .
```

### Implantar com Helm

```bash
cd app
helm install valsec ./chart
```

### Acessar as Aplicações

- Versão A (Rosa): http://valsec-a.example.com
- Versão B (Azul): http://valsec-b.example.com

## Configuração

Você pode personalizar a implantação editando o arquivo `values.yaml` no diretório do chart.

FROM golang:1.25-alpine AS builder

# Definir variáveis de build para segurança
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Usar diretório de trabalho seguro
WORKDIR /build

# Copiar apenas os arquivos necessários
COPY main.go go.mod ./

# Compilar com flags de segurança
RUN go build -ldflags="-s -w" -o valsec .

# Verificar vulnerabilidades (se disponível)
RUN if [ -x "$(command -v govulncheck)" ]; then govulncheck ./...; fi

# Imagem final mínima
FROM alpine:3.18

# Adicionar labels de segurança e metadados
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.url="https://github.com/valsec" \
      org.opencontainers.image.source="https://github.com/valsec" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Valsec" \
      org.opencontainers.image.title="Valsec" \
      org.opencontainers.image.description="Aplicação Valsec para testes de segurança"

# Atualizar pacotes e adicionar dependências de segurança
RUN apk update && \
    apk add --no-cache ca-certificates tzdata && \
    apk upgrade && \
    rm -rf /var/cache/apk/*

# Criar usuário não-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Configurar diretório da aplicação
WORKDIR /app

# Copiar o binário compilado
COPY --from=builder --chown=appuser:appgroup /build/valsec .

# Definir permissões adequadas
RUN chmod 550 /app/valsec && \
    chown -R appuser:appgroup /app

# Configurar variáveis de ambiente
ENV PORT=8080

# Expor porta
EXPOSE 8080

# Configurar healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/ || exit 1

# Mudar para usuário não-root
USER appuser

# Executar com o mínimo de privilégios
CMD ["./valsec"]

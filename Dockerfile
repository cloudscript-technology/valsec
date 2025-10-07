FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY main.go .

RUN go build -o valsec-app .

FROM alpine:3.18

WORKDIR /app
COPY --from=builder /app/valsec-app .

ENV PORT=8080

EXPOSE 8080

CMD ["./valsec-app"]

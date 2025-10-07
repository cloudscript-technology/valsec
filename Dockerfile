FROM golang:1.24-alpine AS builder

WORKDIR /
COPY main.go .
COPY go.mod .

RUN go build -o valsec .

FROM alpine:3.18

WORKDIR /app
COPY --from=builder /valsec .

ENV PORT=8080

EXPOSE 8080

CMD ["./valsec"]

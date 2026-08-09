# syntax=docker/dockerfile:1
# ApexCore — центральная шина (gRPC + gateway + WS + metrics).
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY core/go.mod core/go.sum ./
RUN go mod download
COPY core ./
RUN go build -ldflags="-s -w" -o /apexcore ./cmd/apexcore

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /apexcore /usr/local/bin/apexcore
EXPOSE 50051 8080
ENTRYPOINT ["apexcore"]

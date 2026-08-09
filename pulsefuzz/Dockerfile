# syntax=docker/dockerfile:1
# PulseFuzz — Go coverage-guided фаззер.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY pulsefuzz/go.mod pulsefuzz/go.sum ./
RUN go mod download
COPY pulsefuzz ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /pulsefuzz .

FROM alpine:3.20
RUN adduser -D -u 10001 pulsefuzz
COPY --from=build /pulsefuzz /usr/local/bin/pulsefuzz
USER pulsefuzz
ENTRYPOINT ["pulsefuzz"]

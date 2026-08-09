# syntax=docker/dockerfile:1
# HexEye — HTTP-сервис статического анализа (Python).
# Быстрый Rust-вариант ядра (zero-copy, capstone, CFG) — в hexeye/rust/.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
  && rm -rf /var/lib/apt/lists/*

COPY hexeye/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY hexeye /app/hexeye
EXPOSE 9092
ENTRYPOINT ["python", "-m", "hexeye.server"]
CMD ["--listen", "0.0.0.0:9092"]

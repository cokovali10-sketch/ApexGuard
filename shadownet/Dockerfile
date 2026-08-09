# syntax=docker/dockerfile:1
# ShadowNet — honeypot-сервис.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY shadownet/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shadownet /app/shadownet

# Порт SSH-honeypot + HTTP API (ApexCore integration).
EXPOSE 2222 8081

ENTRYPOINT ["python", "-m", "shadownet.honeypot.ssh_server"]
CMD ["--host", "0.0.0.0", "--port", "2222", "--docker"]

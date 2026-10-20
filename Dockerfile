FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
# Official CLI archive; digest checked before extracting the executable.
ARG BW_CLI_VERSION=2026.9.1
ARG BW_CLI_SHA256=84289eaf59d691f04242605112f21b00e8dba65acdedbc60dde001a2860f2097
RUN BW_CLI_VERSION="$BW_CLI_VERSION" BW_CLI_SHA256="$BW_CLI_SHA256" python -c 'import os,hashlib,io,pathlib,urllib.request,zipfile; v=os.environ["BW_CLI_VERSION"]; data=urllib.request.urlopen(f"https://github.com/bitwarden/clients/releases/download/cli-v{v}/bw-linux-{v}.zip",timeout=120).read(); assert hashlib.sha256(data).hexdigest()==os.environ["BW_CLI_SHA256"]; p=pathlib.Path("/usr/local/bin/bw"); p.write_bytes(zipfile.ZipFile(io.BytesIO(data)).read("bw")); p.chmod(0o755)'
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN mkdir -p /var/lib/vault-gateway/bw-homes && chown -R 1000:1000 /app /var/lib/vault-gateway
USER 1000:1000
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health",timeout=3)' || exit 1
# Do not log bearer-capability requests or submitted content.
CMD ["python", "-m", "uvicorn", "app.main:asgi_app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log", "--log-level", "warning"]

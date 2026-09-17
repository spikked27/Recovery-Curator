FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/spikked27/Recovery-Curator" \
      org.opencontainers.image.description="Non-destructive recovery triage and curation for Unraid"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOURCE_ROOT=/source \
    REFERENCE_ROOT=/known-good \
    OUTPUT_ROOT=/output \
    QUARANTINE_ROOT=/quarantine \
    DATA_DIR=/config \
    ALLOW_ACTIONS=false \
    PUID=99 \
    PGID=100 \
    OUTPUT_UID=99 \
    OUTPUT_GID=100 \
    UMASK=002

RUN apt-get update && apt-get install -y --no-install-recommends \
      ffmpeg libimage-exiftool-perl libmagic1 qpdf tini gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/recovery-curator
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8188
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8188", "--workers", "1", "--threads", "4", "--timeout", "0", "app.main:app"]

# Rathnone gateway — reproducible, fail-closed container.
#
# The frozen governance spine (fleet + exchange + scripts, pinned at
# vendor/fleet_spine/PINNED_COMMIT) is vendored into the image at build time,
# so the runtime NEVER reaches out to a mutable external repo. sovereign-agent-fleet
# stays untouched; this is a read-only snapshot baked into the image.
#
# BUILD/RUN PLATFORM: build and run with `--platform linux/amd64`. On Apple
# Silicon, the arm64 `cryptography` wheel hits a SIGILL (exit 132) inside the
# Docker VM's arm64 emulation during ed25519 native init. Running the amd64
# image under Rosetta is stable (verified). So:
#   docker build --platform=linux/amd64 -t rathnone:local .
#   docker run   --platform=linux/amd64 -p 127.0.0.1:8765:8765 ... rathnone:local
FROM --platform=linux/amd64 python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Vendored frozen spine first (best layer cache): change only when the pin bumps.
COPY vendor/fleet_spine ./vendor/fleet_spine
# Runtime deps.
COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# Application source.
COPY src ./src
COPY tests ./tests

# Make the vendored spine importable for every interpreter in the image
# (system + any venv). Two mechanisms, both harmless if redundant.
ENV PYTHONPATH=/app/vendor/fleet_spine
RUN SITE=$(python -c "import site;print(site.getsitepackages()[0])") && \
    echo "/app/vendor/fleet_spine" > "$SITE/fleet_overlay.pth"

# Run as a non-root user.
RUN useradd --create-home --uid 10001 rathnone
USER rathnone

# Defaults are SAFE: no settlement ceiling and an effectively-unlimited live rate
# are NOT silently applied at runtime — the service imports fine, but operator
# MUST set RATHNONE_MAX_SETTLEMENT_VALUE_WEI / RATHNONE_LIVE_RATE_MAX via env
# (compose, k8s secret, or `docker run -e`) to get real protection. A malformed
# value fails container start (fail-closed), it never quietly disables a guard.
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/safety').status==200 else 1)"

CMD ["sh", "-c", "python -m uvicorn src.service.app:app --host ${RATHNONE_HOST:-0.0.0.0} --port ${RATHNONE_PORT:-8765}"]

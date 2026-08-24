# Stage 1: Build wheel artifact
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir hatchling build

# Copy sources required for package build
COPY pyproject.toml PYPI.md LICENSE SKILL.md immunity-agent.pth ./
COPY advisories/ advisories/
COPY keys/ keys/
COPY templates/ templates/
COPY docs/ docs/
COPY prismor/ prismor/
COPY supplychain/ supplychain/
COPY adapters/ adapters/

# Build standalone wheel
RUN python -m build --wheel --outdir /build/dist

# Stage 2: Runtime image
FROM python:3.12-slim AS runner

LABEL org.opencontainers.image.title="Prismor" \
      org.opencontainers.image.description="Runtime security for AI coding agents" \
      org.opencontainers.image.url="https://prismor.dev" \
      org.opencontainers.image.source="https://github.com/PrismorSec/prismor" \
      org.opencontainers.image.licenses="Apache-2.0"

# Create unprivileged runtime user with deterministic UID/GID
RUN groupadd -g 10001 prismor && \
    useradd -u 10001 -g prismor -m -s /bin/bash prismor

# Copy and install built wheel
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Create state directory and default workspace mount point
RUN mkdir -p /home/prismor/.prismor /workspace && \
    chown -R prismor:prismor /home/prismor /workspace && \
    chmod 700 /home/prismor/.prismor

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PRISMOR_HOME=/home/prismor/.prismor \
    PRISMOR_WORKSPACE=/workspace \
    PRISMOR_NO_UPDATE_CHECK=1 \
    PATH="/home/prismor/.local/bin:$PATH"

WORKDIR /workspace
USER 10001:10001

# Dashboard (7070) and Eval server (7071)
EXPOSE 7070 7071

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD prismor status > /dev/null 2>&1 || exit 1

ENTRYPOINT ["prismor"]
CMD ["dashboard", "--host", "0.0.0.0", "--port", "7070", "--no-open"]

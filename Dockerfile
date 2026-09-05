# ── Cisco IOS Compliance Platform ────────────────────────────────────────────
# Multi-stage build: deps cached separately from source code
# Non-root user for security best practice
# ─────────────────────────────────────────────────────────────────────────────

# ---------- Stage 1: Dependency builder ----------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools needed to compile asyncpg / other C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---------- Stage 2: Runtime image ----------
FROM python:3.12-slim AS runtime

# Runtime system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
ARG USERNAME=fastapi
ARG UID=1000
RUN adduser --disabled-password --gecos "" --uid $UID $USERNAME

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY app/ ./app/

# Switch to non-root user
USER $USERNAME

EXPOSE 8000

# Uvicorn in production mode
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

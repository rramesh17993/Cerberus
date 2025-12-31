# 🏗️ Backend Dockerfile
# Multi-stage build for development and production

# ==========================================
# 🐍 Base Stage
# ==========================================
FROM python:3.10-slim as base

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ==========================================
# 🏗️ Builder Stage
# ==========================================
FROM base as builder

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ==========================================
# 🚀 Production Stage
# ==========================================
FROM base as production

COPY --from=builder /install /usr/local
COPY . .

# Create non-root user
RUN useradd -m securescan && \
    chown -R securescan:securescan /app

USER securescan

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ==========================================
# 🛠️ Development Stage
# ==========================================
FROM base as development

COPY requirements.txt .
COPY requirements-dev.txt .

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-dev.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

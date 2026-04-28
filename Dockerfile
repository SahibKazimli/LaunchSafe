# =============================================================================
# LaunchSafe — production container (designed for Google Cloud Run)
# =============================================================================
#
# Build context is the REPO ROOT (so we can copy both backend/ and frontend/).
#
#   gcloud run deploy launchsafe \
#       --source . \
#       --region europe-north1 \
#       --allow-unauthenticated \
#       --set-env-vars GEMINI_API_KEY=...,LAUNCHSAFE_LLM_MODEL=gemini-3-flash-preview
#
# Cloud Run injects PORT (default 8080); we bind uvicorn to it.
#
# Frontend: multi-stage build runs Vite; FastAPI serves dist/*.html and /assets/*.
# =============================================================================

FROM node:22-alpine AS frontend-build

WORKDIR /app/frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080

# git is required by GitPython (clone_github) at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so the layer caches across code changes
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

# Run as non-root
RUN useradd --system --no-create-home --uid 1001 launchsafe \
    && chown -R launchsafe:launchsafe /app
USER launchsafe

# uvicorn must run from /app/backend so `main:app` resolves and the
# `agents.*` imports work the same way they do locally.
WORKDIR /app/backend

EXPOSE 8080

# Cloud Run sends SIGTERM with up to 10s grace; uvicorn handles it.
# Single worker is intentional: scan_store is in-process state.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1 --timeout-keep-alive 75"]

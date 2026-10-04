# The file manager: the web app built, then the backend serving it. Build context: the repository root (for the rowstile command)
FROM node:24-slim AS web
WORKDIR /web
COPY examples/filemanager/frontend/package.json examples/filemanager/frontend/package-lock.json ./
RUN npm ci
COPY examples/filemanager/frontend/ ./
RUN npm run build

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /fm/backend
COPY examples/filemanager/backend/pyproject.toml examples/filemanager/backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY examples/filemanager/backend/ ./
COPY examples/filemanager/db/ /fm/db/
# the rowstile command, which migrate.py runs to apply the policy
COPY core/authzlib /core/authzlib
COPY core/cli /core/cli
COPY --from=web /web/dist /fm/frontend/dist
ENV PATH=/fm/backend/.venv/bin:$PATH
# migrations and the policy first, as the database owner; then the app, as fm_app
CMD ["sh", "-c", "python /fm/db/migrate.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

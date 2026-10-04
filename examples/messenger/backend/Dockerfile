# The messenger: the web app built, then the backend serving it. Build context: the repository root (for the rowstile command)
FROM node:24-slim AS web
WORKDIR /web
COPY examples/messenger/frontend/package.json examples/messenger/frontend/package-lock.json ./
RUN npm ci
COPY examples/messenger/frontend/ ./
RUN npm run build

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /ms/backend
COPY examples/messenger/backend/pyproject.toml examples/messenger/backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY examples/messenger/backend/ ./
COPY examples/messenger/db/ /ms/db/
# the rowstile command, which migrate.py runs to apply the policy
COPY core/authzlib /core/authzlib
COPY core/cli /core/cli
COPY --from=web /web/dist /ms/frontend/dist
ENV PATH=/ms/backend/.venv/bin:$PATH
# migrations and the policy first, as the database owner; then the app, as ms_app
CMD ["sh", "-c", "python /ms/db/migrate.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

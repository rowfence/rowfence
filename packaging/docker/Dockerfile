# The rowfence command as an image, for CI and for machines without Python: the rowfence package (the command
# and the Python SDK) built from this repository, and git (rowfence review reads the base branch with it).
#   docker build -t rowfence-cli -f packaging/docker/Dockerfile .
#   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/work" -e DATABASE_URL rowfence-cli migrate
# (-u: what it writes into the project, a migration, the lock file, is then the caller's, not root's)
FROM python:3.13-slim AS build
COPY core/authzlib /src/core/authzlib
COPY core/cli /src/core/cli
COPY sdk/python /src/sdk/python
RUN pip wheel --no-cache-dir --no-deps -w /wheels /src/sdk/python

FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
 && git config --system --add safe.directory '*'
WORKDIR /work
ENTRYPOINT ["rowfence"]
CMD ["--help"]

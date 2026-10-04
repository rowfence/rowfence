# Postgres for developing and testing rowstile: the stock image, plus python3, git (rowstile review reads the
# base branch with it) and the rowstile command. rowstile needs nothing in the database but plain SQL and
# PL/pgSQL: the command compiles the policy and applies it as the tables' owner, with no superuser.
#   docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .
#   docker run -d --name pga -e POSTGRES_HOST_AUTH_METHOD=trust rowstile:16
#   docker exec -u postgres pga rowstile apply /path/to/policy.authz
ARG PG_MAJOR=16
FROM postgres:${PG_MAJOR}
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 git \
 && rm -rf /var/lib/apt/lists/*
# the suites run the mounted repository as root: no __pycache__ left in it that its owner can't remove
ENV PYTHONDONTWRITEBYTECODE=1
COPY core/authzlib /opt/rowstile/authzlib
COPY core/cli /opt/rowstile/cli
RUN printf '#!/bin/sh\nexec python3 /opt/rowstile/cli/rowstile_cli.py "$@"\n' > /usr/local/bin/rowstile \
 && chmod 755 /usr/local/bin/rowstile

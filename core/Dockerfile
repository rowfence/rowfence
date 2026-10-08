# Postgres for developing and testing rowstile: the stock image, plus python3, git (rowstile review reads the
# base branch with it) and the rowstile command. rowstile needs nothing in the database but plain SQL and
# PL/pgSQL: the command compiles the policy and applies it as the tables' owner, with no superuser.
#   docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .
#   docker run -d --name pga -e POSTGRES_HOST_AUTH_METHOD=trust rowstile:16
#   docker exec -u postgres pga rowstile apply /path/to/policy.authz
# With --build-arg COVERAGE=1 it also measures what the suites run (ci.sh --coverage): coverage.py, which starts
# in every Python process when COVERAGE_PROCESS_START names its settings (run_tests.sh sets it).
ARG PG_MAJOR=16
FROM postgres:${PG_MAJOR}
ARG COVERAGE=
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 git ${COVERAGE:+python3-coverage} \
 && rm -rf /var/lib/apt/lists/*
RUN if [ -n "$COVERAGE" ]; then \
      echo "import coverage; coverage.process_startup()" > /usr/lib/python3/dist-packages/rowstile-coverage.pth; fi
# the suites run the mounted repository as root: no __pycache__ left in it that its owner can't remove
ENV PYTHONDONTWRITEBYTECODE=1
COPY core/authzlib /opt/rowstile/authzlib
COPY core/cli /opt/rowstile/cli
RUN printf '#!/bin/sh\nexec python3 /opt/rowstile/cli/rowstile_cli.py "$@"\n' > /usr/local/bin/rowstile \
 && chmod 755 /usr/local/bin/rowstile

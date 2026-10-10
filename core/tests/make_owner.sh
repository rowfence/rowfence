#!/bin/bash
# make_owner.sh: the role the suites run as: authz_owner, not a superuser, with CREATEDB and CREATEROLE, and
# SET on the roles it creates (so it can SET ROLE app_user, as a migration role on managed Postgres can).
# Run as a superuser:  PGUSER=postgres tests/make_owner.sh; then PGUSER=authz_owner tests/<suite>.sh
set -u
psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "DO \$o\$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_owner') THEN
      CREATE ROLE authz_owner LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS;
    END IF; END \$o\$" -c "ALTER ROLE authz_owner SET createrole_self_grant = 'set, inherit'" >/dev/null
# app_user, the role the suites' apps connect as, made once here by authz_owner, as their schemas would make it: they
# make it when it isn't there, and two doing so at once (run_tests.sh's lanes) collide
PGUSER=authz_owner psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "DO \$o\$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
  END \$o\$" >/dev/null

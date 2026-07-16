#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_APP_USER:?POSTGRES_APP_USER is required}"
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD is required}"

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --set=owner_user="$POSTGRES_USER" \
  --set=app_user="$POSTGRES_APP_USER" \
  --set=app_password="$POSTGRES_APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I', :'app_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

SELECT format(
  'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
  :'app_user',
  :'app_password'
)
\gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'app_user')
\gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app_user')
\gexec
SELECT format(
  'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I',
  :'app_user'
)
\gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'app_user')
\gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
  :'owner_user',
  :'app_user'
)
\gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I',
  :'owner_user',
  :'app_user'
)
\gexec

-- The application may append and inspect audit events, but it must never rewrite history.
SELECT format(
  'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.audit_logs FROM %I',
  :'app_user'
)
WHERE to_regclass('public.audit_logs') IS NOT NULL
\gexec
SELECT format(
  'GRANT SELECT, INSERT ON TABLE public.audit_logs TO %I',
  :'app_user'
)
WHERE to_regclass('public.audit_logs') IS NOT NULL
\gexec
SELECT format(
  'GRANT USAGE, SELECT ON SEQUENCE public.audit_logs_id_seq TO %I',
  :'app_user'
)
WHERE to_regclass('public.audit_logs_id_seq') IS NOT NULL
\gexec

-- The event trigger reapplies the restriction after Alembic creates or alters audit_logs,
-- so broad owner default privileges cannot accidentally restore mutation privileges.
SELECT format(
  $definition$
  CREATE OR REPLACE FUNCTION public.enforce_audit_log_runtime_privileges()
  RETURNS event_trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, public
  AS $function$
  BEGIN
    IF to_regclass('public.audit_logs') IS NOT NULL THEN
      EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.audit_logs FROM %1$I';
      EXECUTE 'GRANT SELECT, INSERT ON TABLE public.audit_logs TO %1$I';
    END IF;
  END
  $function$
  $definition$,
  :'app_user'
)
\gexec

REVOKE ALL ON FUNCTION public.enforce_audit_log_runtime_privileges() FROM PUBLIC;
DROP EVENT TRIGGER IF EXISTS enforce_audit_log_runtime_privileges;
CREATE EVENT TRIGGER enforce_audit_log_runtime_privileges
  ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE')
  EXECUTE FUNCTION public.enforce_audit_log_runtime_privileges();
SQL

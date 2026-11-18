#!/usr/bin/env bash

set -e

: "${TRMM_USER:=tactical}"
: "${TRMM_PASS:=tactical}"
: "${POSTGRES_HOST:=tactical-postgres}"
: "${POSTGRES_PORT:=5432}"
: "${POSTGRES_USER:=tactical}"
: "${POSTGRES_PASS:=tactical}"
: "${POSTGRES_DB:=tacticalrmm}"
: "${MESH_SERVICE:=tactical-meshcentral}"
: "${MESH_WS_URL:=ws://${MESH_SERVICE}:4443}"
: "${MESH_USER:=meshcentral}"
: "${MESH_PASS:=meshcentralpass}"
: "${MESH_HOST:=tactical-meshcentral}"
: "${API_HOST:=tactical-backend}"
: "${APP_HOST:=tactical-frontend}"
: "${REDIS_HOST:=tactical-redis}"
: "${SKIP_UWSGI_CONFIG:=0}"
: "${TRMM_DISABLE_WEB_TERMINAL:=True}"
: "${TRMM_DISABLE_SERVER_SCRIPTS:=True}"
: "${TRMM_DISABLE_SSO:=False}"
# security hardening, see api/tacticalrmm/tacticalrmm/settings.py
: "${TRMM_NUM_PROXIES:=1}"
: "${TRMM_DISABLE_REPORTING:=True}"
: "${TRMM_URL_ACTION_ALLOW_PRIVATE:=False}"
: "${TRMM_ENFORCE_2FA:=True}"

: "${CERT_PRIV_PATH:=${TACTICAL_DIR}/certs/privkey.pem}"
: "${CERT_PUB_PATH:=${TACTICAL_DIR}/certs/fullchain.pem}"

function check_tactical_ready {
  sleep 15
  until [ -f "${TACTICAL_READY_FILE}" ]; do
    echo "waiting for init container to finish install or update..."
    sleep 10
  done
}

# tactical-init
if [ "$1" = 'tactical-init' ]; then

  # refuse to install with the well-known default credentials
  # (MESH_PASS is checked by the meshcentral container, which receives it)
  for pair in "TRMM_PASS:tactical" "POSTGRES_PASS:tactical"; do
    var="${pair%%:*}"
    if [ -z "${!var}" ] || [ "${!var}" = "${pair#*:}" ]; then
      echo "ERROR: ${var} is empty or the default value; set a strong secret" >&2
      exit 1
    fi
  done

  test -f "${TACTICAL_READY_FILE}" && rm "${TACTICAL_READY_FILE}"

  # copy container data to volume
  rsync -a --no-perms --no-owner --delete --exclude "tmp/*" --exclude "certs/*" --exclude="api/tacticalrmm/private/*" "${TACTICAL_TMP_DIR}/" "${TACTICAL_DIR}/"

  mkdir -p /meshcentral-data
  mkdir -p ${TACTICAL_DIR}/tmp
  mkdir -p ${TACTICAL_DIR}/certs
  mkdir -p ${TACTICAL_DIR}/reporting
  mkdir -p ${TACTICAL_DIR}/reporting/assets
  mkdir -p /mongo/data/db
  mkdir -p /redis/data
  touch /meshcentral-data/.initialized && chown -R 1000:1000 /meshcentral-data
  touch ${TACTICAL_DIR}/tmp/.initialized && chown -R 1000:1000 ${TACTICAL_DIR}
  touch ${TACTICAL_DIR}/certs/.initialized && chown -R 1000:1000 ${TACTICAL_DIR}/certs
  touch /mongo/data/db/.initialized && chown -R 1000:1000 /mongo/data/db
  touch /redis/data/.initialized && chown -R 1000:1000 /redis/data
  touch ${TACTICAL_DIR}/reporting && chown -R 1000:1000 ${TACTICAL_DIR}/reporting
  mkdir -p ${TACTICAL_DIR}/api/tacticalrmm/private/exe
  mkdir -p ${TACTICAL_DIR}/api/tacticalrmm/private/log
  touch ${TACTICAL_DIR}/api/tacticalrmm/private/log/django_debug.log

  until (echo >/dev/tcp/"${POSTGRES_HOST}"/"${POSTGRES_PORT}") &>/dev/null; do
    echo "waiting for postgresql container to be ready..."
    sleep 5
  done

  until (echo >/dev/tcp/"${MESH_SERVICE}"/4443) &>/dev/null; do
    echo "waiting for meshcentral container to be ready..."
    sleep 5
  done

  # configure django settings
  MESH_TOKEN=$(cat ${TACTICAL_DIR}/tmp/mesh_token)
  ADMINURL=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 70 | head -n 1)
  DJANGO_SEKRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 80 | head -n 1)
  # NATS admin password (commands every agent) is kept apart from SECRET_KEY
  NATS_ADMIN_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 80 | head -n 1)
  # quote secrets as Python literals so special characters can't break or inject
  PG_PASS_LITERAL=$(POSTGRES_PASS="${POSTGRES_PASS}" python -c 'import os; print(repr(os.environ["POSTGRES_PASS"]))')
  BASE_DOMAIN=$(echo "import tldextract; no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=()); extracted = no_fetch_extract('${API_HOST}'); print(f'{extracted.domain}.{extracted.suffix}')" | python)
  # cookie domain: set TRMM_COOKIE_DOMAIN (e.g. rmm.example.com) to keep the
  # session cookie off sibling subdomains; SESSION_COOKIE_DOMAIN kept for compat
  : "${TRMM_COOKIE_DOMAIN:=${SESSION_COOKIE_DOMAIN:-$BASE_DOMAIN}}"

  localvars="$(
    cat <<EOF
SECRET_KEY = '${DJANGO_SEKRET}'

DEBUG = False

DOCKER_BUILD = True

CERT_FILE = '${CERT_PUB_PATH}'
KEY_FILE = '${CERT_PRIV_PATH}'

EXE_DIR = '/opt/tactical/api/tacticalrmm/private/exe'
LOG_DIR = '/opt/tactical/api/tacticalrmm/private/log'

SCRIPTS_DIR = '/opt/tactical/community-scripts'

ALLOWED_HOSTS = ['${API_HOST}', '${APP_HOST}', 'tactical-backend']

ADMIN_URL = '${ADMINURL}/'

CORS_ORIGIN_WHITELIST = ['https://${APP_HOST}']

TRMM_COOKIE_DOMAIN = '${TRMM_COOKIE_DOMAIN}'
CSRF_TRUSTED_ORIGINS = ['https://${API_HOST}', 'https://${APP_HOST}']

HEADLESS_FRONTEND_URLS = {'socialaccount_login_error': 'https://${APP_HOST}/account/provider/callback'}

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': '${POSTGRES_DB}',
        'USER': '${POSTGRES_USER}',
        'PASSWORD': ${PG_PASS_LITERAL},
        'HOST': '${POSTGRES_HOST}',
        'PORT': '${POSTGRES_PORT}',
    }
}

MESH_USERNAME = '${MESH_USER}'
MESH_SITE = 'https://${MESH_HOST}'
MESH_TOKEN_KEY = '${MESH_TOKEN}'
REDIS_HOST    = '${REDIS_HOST}'
MESH_WS_URL = '${MESH_WS_URL}'
ADMIN_ENABLED = False
TRMM_DISABLE_WEB_TERMINAL = ${TRMM_DISABLE_WEB_TERMINAL}
TRMM_DISABLE_SERVER_SCRIPTS = ${TRMM_DISABLE_SERVER_SCRIPTS}
TRMM_DISABLE_SSO = ${TRMM_DISABLE_SSO}

NATS_ADMIN_PASSWORD = '${NATS_ADMIN_PASSWORD}'
ROOT_USER = '${TRMM_USER}'
TRMM_NUM_PROXIES = ${TRMM_NUM_PROXIES}
TRMM_DISABLE_REPORTING = ${TRMM_DISABLE_REPORTING}
TRMM_URL_ACTION_ALLOW_PRIVATE = ${TRMM_URL_ACTION_ALLOW_PRIVATE}
TRMM_ENFORCE_2FA = ${TRMM_ENFORCE_2FA}
EOF
  )"

  (umask 077 && echo "${localvars}" >${TACTICAL_DIR}/api/tacticalrmm/local_settings.py)

  # run migrations and init scripts
  python manage.py pre_update_tasks
  python manage.py migrate --no-input
  python manage.py generate_json_schemas
  python manage.py get_webtar_url >${TACTICAL_DIR}/tmp/web_tar_url
  python manage.py collectstatic --no-input
  python manage.py initial_db_setup
  python manage.py initial_mesh_setup
  python manage.py load_chocos
  python manage.py load_community_scripts
  python manage.py reload_nats
  python manage.py create_natsapi_conf

  if [ "$SKIP_UWSGI_CONFIG" = 0 ]; then
    python manage.py create_uwsgi_conf
  fi

  python manage.py create_installer_user
  python manage.py clear_redis_celery_locks
  python manage.py post_update_tasks

  # create super user
  echo "Creating dashboard user if it doesn't exist"
  # credentials go through the environment, never into the Python source
  echo "import os; from accounts.models import User; u, p = os.environ['TRMM_USER'], os.environ['TRMM_PASS']; User.objects.create_superuser(u, 'admin@example.com', p) if not User.objects.filter(username=u).exists() else 0;" | TRMM_USER="${TRMM_USER}" TRMM_PASS="${TRMM_PASS}" python manage.py shell

  # chown everything to tactical user
  echo "Updating permissions on files"
  chown -R "${TACTICAL_USER}":"${TACTICAL_USER}" "${TACTICAL_DIR}"

  # create install ready file
  echo "Creating install ready file"
  su -c "echo 'tactical-init' > ${TACTICAL_READY_FILE}" "${TACTICAL_USER}"

fi

# backend container
if [ "$1" = 'tactical-backend' ]; then
  check_tactical_ready
  uwsgi ${TACTICAL_DIR}/api/app.ini
fi

if [ "$1" = 'tactical-celery' ]; then
  check_tactical_ready
  celery -A tacticalrmm worker --autoscale=20,2 -l info
fi

if [ "$1" = 'tactical-celerybeat' ]; then
  check_tactical_ready
  test -f "${TACTICAL_DIR}/api/celerybeat.pid" && rm "${TACTICAL_DIR}/api/celerybeat.pid"
  celery -A tacticalrmm beat -l info
fi

# websocket container
if [ "$1" = 'tactical-websockets' ]; then
  check_tactical_ready

  export DJANGO_SETTINGS_MODULE=tacticalrmm.settings

  uvicorn --host 0.0.0.0 --port 8383 --forwarded-allow-ips='*' tacticalrmm.asgi:application
fi

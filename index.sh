#!/bin/bash

ALL=false
HELP=false
DOMAINS=()
LETSENCRYPT=false
# From https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
MODERN_CIHPERS="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
LEGACY_CIPHERS="ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS"
UNSAFE_CIPHERS="ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP"
CIPHERS="$MODERN_CIPHERS"

MODERN_TLS="TLSv1.2"
LEGACY_TLS="TLSv1.2 TLSv1.1 TLSv1"
UNSAFE_TLS="TLSv1.2 TLSv1.1 TLSv1 SSLv3"
TLS_VERSIONS="$MODERN_TLS"

while true; do
  case "$1" in
    --letsencrypt)     LETSENCRYPT=true; shift ;;
    -l)                LETSENCRYPT=true; shift ;;
    --all)             ALL=true; shift ;;
    -a)                ALL=true; shift ;;
    --domain)          DOMAINS+=("$2"); shift; shift ;;
    -d)                DOMAINS+=("$2"); shift; shift ;;
    --help)            HELP=true; shift ;;
    -h)                HELP=true; shift ;;
    --key)             KEY="$2"; shift; shift ;;
    -k)                KEY="$2"; shift; shift ;;
    --crt)             CERT="$2"; shift; shift ;;
    --cert)            CERT="$2"; shift; shift ;;
    -c)                CERT="$2"; shift; shift ;;
    --dhparam)         DHPARAM="$2"; shift; shift ;;
    -p)                DHPARAM="$2"; shift; shift ;;
    --modern-ciphers)  CIPHERS="$MODERN_CIPHERS"; shift ;;
    --legacy-ciphers)  CIPHERS="$LEGACY_CIPHERS"; shift ;;
    --unsafe-ciphers)  CIPHERS="$UNSAFE_CIPHERS"; shift ;;
    --modern-tls)      TLS_VERSIONS="$MODERN_TLS"; shift ;;
    --legacy-tls)      TLS_VERSIONS="$LEGACY_TLS"; shift ;;
    --unsafe-tls)      TLS_VERSIONS="$UNSAFE_TLS"; shift ;;
    *)                 break ;;
  esac
done

error () {
  echo "$1" >&2
  exit 1
}

check_program () {
  [ "$(which $1) 2>/dev/null" != "" ] && return 0
  error "$1 is required"
}

check_file () {
  [ -f "$1" ] && return 0
  error "$1 does not exist"
}

if $HELP; then
  cat <<EOF_HELP
Usage: add-nginx-ssl [options]
  --key,            -k  ssl-private-key.key (required if no --letsencrypt)
  --cert,           -c  ssl-certificate.crt (required if no --letsencrypt)
  --letsencrypt     -l  use letsencrypt to issue and auto renew certs
  --dhparam,        -p  dhparam.pem
  --all,            -a  (add ssl to all domains)
  --domain,         -d  example.com
  --modern-ciphers      accept modern ciphers (default)
  --legacy-ciphers      accept legacy ciphers
  --unsafe-ciphers      accept all, including some dangerous, ciphers
  --modern-tls          accept only TLS v1.2 (default)
  --legacy-tls          accept all TLS versions
  --unsafe-tls          accept all TLS versions and SSLv3

EOF_HELP
  exit 0
fi

check_program nginx

[ ! -d /etc/nginx/conf.d ] && error "/etc/nginx/conf.d does not exist. Is nginx installed?"

[ "$KEY" == "" ] && ! $LETSENCRYPT && error "--key is required"
[ "$CERT" == "" ] && ! $LETSENCRYPT && error "--cert is required"
[ "$DOMAINS" == "" ] && ! $ALL && error "--domain or --all is required"
$ALL && DOMAINS+=('-')

[ ! -O /etc/nginx/conf.d ] && SUDO_MAYBE=sudo

if $LETSENCRYPT; then
  check_program openssl
  check_program certbot

  FIRST_DOMAIN="${DOMAINS[0]}"
  LETSENCRYPT_CERTS="/etc/letsencrypt/live/$FIRST_DOMAIN"
  $SUDO_MAYBE mkdir -p /var/www/letsencrypt

  if [ ! -f /etc/nginx/conf.d/ssl.conf ] || ! grep '/.well-known/acme-challenge' /etc/nginx/conf.d/ssl.conf >/dev/null 2>/dev/null; then
    cat <<EOF_LETSENCRYPT > /etc/nginx/conf.d/ssl.conf
server {
  listen 80;
  server_name _;

  location /.well-known/acme-challenge {
    root /var/www/letsencrypt;
  }
}
EOF_LETSENCRYPT

    $SUDO_MAYBE nginx -s reload

    DHPARAM="$LETSENCRYPT_CERTS/dhparam2048.pem"
    [ ! -f "$DHPARAM" ] && openssl dhparam -outform pem -out "$DHPARAM" 2048
  fi
fi

if [ "$DHPARAM" != "" ]; then
  check_file "$DHPARAM"
  SSL_DHPARAM="ssl_dhparam $(realpath -s $DHPARAM);";
fi

check_file "$KEY"
check_file "$CERT"

rm -f /tmp/nginx.ssl.conf

for DOMAIN in ${DOMAINS[@]}; do
  [ "$DOMAIN" == "-" ] && DOMAIN='*'
  SERVER_NAME="server_name $DOMAIN;"
  [ "*.${DOMAIN:2}" == "$DOMAIN" ] && WILDCARD_SERVER_NAME="server_name ${DOMAIN:2};"

  cat <<EOF_SSL >> /tmp/nginx.ssl.conf
server {
  listen 80;
  $SERVER_NAME
  $WILDCARD_SERVER_NAME
  return 301 https://\$host\$request_uri;
}
EOF_SSL
done

cat <<EOF_SSL >> /tmp/nginx.ssl.conf
# default config (server_name _; makes this 'base' config)

server {
  listen 80;
  server_name _;

  location /.well-known/acme-challenge {
    root /var/www/letsencrypt;
  }
}

server {
  listen 443 default ssl;
  server_name _;

  ssl_certificate_key $(realpath -s "$KEY");
  ssl_certificate $(realpath -s "$CERT");

  # These this next block of settings came directly from the SSLMate recommend nginx configuration
  # Recommended security settings from https://wiki.mozilla.org/Security/Server_Side_TLS
  ssl_protocols $TLS_VERSIONS;
  ssl_ciphers '$CIPHERS';
  ssl_prefer_server_ciphers on;
  ssl_session_timeout 5m;
  ssl_session_cache shared:SSL:5m;
  ssl_session_tickets off;

  # Enable this if you want HSTS (recommended)
  add_header Strict-Transport-Security max-age=15768000;

  # from https://gist.github.com/konklone/6532544
  # Generated by OpenSSL with the following command:
  # openssl dhparam -outform pem -out dhparam2048.pem 2048
  $SSL_DHPARAM
}
EOF_SSL

$SUDO_MAYBE mv /tmp/nginx.ssl.conf /etc/nginx/conf.d/ssl.conf
$SUDO_MAYBE nginx -s reload

echo "Wrote nginx SSL config to /etc/nginx/conf.d/ssl.conf"

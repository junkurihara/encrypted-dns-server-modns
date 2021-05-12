#! /usr/bin/env bash

CONF_DIR="/opt/encrypted-dns/etc"
KEYS_DIR="/opt/encrypted-dns/etc/keys"
CONFIG_FILE="${CONF_DIR}/encrypted-dns.toml"
LOG_FILE=/var/log/dnscrypt-server/dnscrypt-server.log
LOG_SIZE=10M
LOG_NUM=10

if [ ! -f "$KEYS_DIR/provider_name" ]; then
    exit 1
fi

chown -R _encrypted-dns:_encrypted-dns /opt/dnscrypt-wrapper/etc/keys 2>/dev/null || :
chown -R _encrypted-dns:_encrypted-dns /opt/encrypted-dns/etc/keys 2>/dev/null || :

if [ -f /opt/encrypted-dns/etc/.env ]; then
  source /opt/encrypted-dns/etc/.env
fi

# logrotate
if [ $LOGROTATE_NUM ]; then
  LOG_NUM=${LOGROTATE_NUM}
fi
if [ $LOGROTATE_SIZE ]; then
  LOG_SIZE=${LOGROTATE_SIZE}
fi

cat > /etc/logrotate.conf << EOF
# see "man logrotate" for details
# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
EOF

cat > /etc/logrotate.d/dnscrypt-server << EOF
/var/log/dnscrypt-server/dnscrypt-server.log {
    dateext
    daily
    missingok
    rotate ${LOG_NUM}
    notifempty
    compress
    delaycompress
    dateformat -%Y-%m-%d-%s
    size ${LOG_SIZE}
    copytruncate
}
EOF

cp -p /etc/cron.daily/logrotate /etc/cron.hourly/
service cron start

# run server
if [ $DEBUG ]; then
  RUST_LOG=debug exec /opt/encrypted-dns/sbin/encrypted-dns --config "$CONFIG_FILE" | tee $LOG_FILE
else
  RUST_LOG=info exec /opt/encrypted-dns/sbin/encrypted-dns --config "$CONFIG_FILE" | tee $LOG_FILE
fi
# exec /opt/encrypted-dns/sbin/encrypted-dns --config "$CONFIG_FILE"

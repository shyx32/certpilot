#!/bin/sh
set -e

# 注入测试公钥
if [ -n "${AUTHORIZED_KEY:-}" ]; then
    echo "$AUTHORIZED_KEY" > /home/deploy/.ssh/authorized_keys
    chmod 600 /home/deploy/.ssh/authorized_keys
    chown -R deploy:deploy /home/deploy/.ssh
fi

/usr/sbin/sshd -e
exec nginx -g 'daemon off;'

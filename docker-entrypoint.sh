#!/bin/sh
# If config.json is missing (fresh volume mount), copy defaults
if [ ! -f /newserv/system/config.json ]; then
    echo "No config.json found, copying defaults from /newserv/system-defaults/..."
    cp -rn /newserv/system-defaults/* /newserv/system/
fi

exec "$@"

#!/bin/sh
# Copy any default files missing from the volume (fresh mount, or files
# added/moved by an upstream update since the volume was last populated).
# cp -rn never overwrites files that already exist, so persistent data
# (config.json, players/, teams/, licenses/) is left untouched.
echo "Syncing missing defaults from /newserv/system-defaults/ into /newserv/system/..."
cp -rn /newserv/system-defaults/* /newserv/system/

exec "$@"

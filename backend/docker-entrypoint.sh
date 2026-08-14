#!/bin/sh
set -eu

# Named volumes created by older images may still be owned by root. Repair only
# the dedicated data directory, then drop privileges before starting the app.
chown -R node:node /data
/usr/local/bin/tool-startup-check
exec gosu node "$@"

#!/bin/sh
# Keep the container alive. Scans run in-process via `docker exec` — the
# persistent process holds no state, it just marks the sandbox as present so
# mutiny's exec-based engine invocations have a stable target.
set -e

exec sleep infinity
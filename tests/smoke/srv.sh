#!/bin/bash
# start|stop|restart the smoke-test server
D="${FP_SMOKE_DIR:-${TMPDIR:-/tmp}/fileparcel-smoke}"
export FILEPARCEL_TAILSCALE_SOCKET="${FILEPARCEL_TAILSCALE_SOCKET:-$D/no-tailscaled.sock}" # never the real tailscaled
PORT="${FP_PORT:-18443}"
HOST="${FP_HOST:-fileparcel.local}"
case "$1" in
stop)
  pkill -f "fileparcel serve --home $D/h1" 2>/dev/null
  for i in $(seq 1 30); do pgrep -f "fileparcel serve --home $D/h1" >/dev/null || break; command sleep 1; done
  pgrep -f "fileparcel serve --home $D/h1" >/dev/null && { echo "STILL RUNNING"; exit 1; }
  echo stopped ;;
start)
  cd "$D" || exit 1
  # One simple command so bash execs it in the child: no subshell is left
  # holding the caller's stdout pipe (subprocess.run would block on it).
  # setsid is util-linux; without it the plain background job plus disown is
  # close enough (the server still survives this script).
  if command -v setsid >/dev/null 2>&1; then
    setsid ./fileparcel serve --home "$D/h1" >> serve.log 2>&1 < /dev/null &
  else
    ./fileparcel serve --home "$D/h1" >> serve.log 2>&1 < /dev/null &
  fi
  disown 2>/dev/null || true
  # The named probe only works when the leaf covers $HOST (run_all.sh pins
  # tls.extra_sans for that); run standalone with a custom FP_HOST against a
  # home whose leaf does not, and it fails on TLS for the full 90 s. The
  # loopback fallback is always covered -- init puts 127.0.0.1 in the leaf.
  # Both probes keep --cacert on this home's own CA, never -k: on a busy
  # machine the port may be held by a *different* server, and reporting that
  # one as ready turns a clean "port taken" abort into a run of TLS failures.
  for i in $(seq 1 90); do
    if curl -sf --max-time 2 --cacert "$D/h1/certs/ca/ca.crt" --resolve "$HOST:$PORT:127.0.0.1" \
         "https://$HOST:$PORT/healthz" >/dev/null 2>&1 ||
       curl -sf --max-time 2 --cacert "$D/h1/certs/ca/ca.crt" \
         "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
      echo "ready ${i}s"; exit 0
    fi
    command sleep 1
  done
  echo "NOT READY"; tail -5 "$D/serve.log"; exit 1 ;;
restart) "$0" stop && "$0" start ;;
esac

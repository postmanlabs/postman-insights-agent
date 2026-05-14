#!/bin/bash
results=""
for bin in /tmp/gomatrix/server_*; do
  name=$(basename $bin)
  pkill -f "/tmp/gomatrix/" 2>/dev/null
  pkill -f apidump-gotls 2>/dev/null
  sleep 1
  $bin > /tmp/srv.log 2>&1 &
  sleep 2
  PID=$(pgrep -f $bin | head -1)
  if [ -z "$PID" ]; then
    printf "%-32s SERVER_FAIL\n" "$name"
    continue
  fi
  /workspace/bin/postman-insights-agent apidump-gotls --pid $PID --duration 6s > /tmp/cap.log 2>&1 &
  sleep 2
  for i in 1 2 3; do curl -sk https://127.0.0.1:9443/ > /dev/null 2>&1; done
  sleep 5
  attached=$(grep -c "attached gotls" /tmp/cap.log)
  reqs=$(grep -c "REQ.*method=GET" /tmp/cap.log)
  resps=$(grep -c "RESP.*status=200" /tmp/cap.log)
  errs=$(grep -c "ERROR" /tmp/cap.log)
  printf "%-32s attach=%s req=%s resp=%s err=%s\n" "$name" "$attached" "$reqs" "$resps" "$errs"
done
pkill -f "/tmp/gomatrix/" 2>/dev/null

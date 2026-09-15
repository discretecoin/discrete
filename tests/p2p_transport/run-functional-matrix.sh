#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != --isolated ]]; then exec unshare --net bash "$0" --isolated "$@"; fi
shift
candidate=$(realpath "${1:?candidate P2pTransportNodeTests}")
baseline=$(realpath "${2:?baseline P2pTransportNodeTests}")
output=$(realpath -m "${3:?new output directory}")
test -x "$candidate" && test -x "$baseline" && test ! -e "$output"
mkdir -p "$output"
ip link set lo up
ip address add 192.0.2.1/32 dev lo
ip -j address > "$output/network.json"

# Both binaries consume exactly these blocks; generation is outside timings.
timeout 100 "$baseline" "$output/freeze" off off exclusive "$output/chain.txt" > "$output/freeze.log" 2>&1
sha256sum "$output/chain.txt" "$candidate" "$baseline" > "$output/inputs.sha256"
timeout 30 "$candidate" --connection-cap "$output/connection-cap" off > "$output/connection-cap.log" 2>&1

server_pid=''
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
run_pair() {
  local name=$1 server=$2 server_mode=$3 client=$4 client_mode=$5 route=$6
  local directory="$output/$name"
  mkdir -p "$directory"
  timeout 100 "$server" --process "$directory" server "$server_mode" "$output/chain.txt" > "$directory/server.log" 2>&1 &
  server_pid=$!
  local client_status=0 server_status=0
  timeout 100 "$client" --process "$directory" client "$client_mode" "$output/chain.txt" "$route" > "$directory/client.log" 2>&1 || client_status=$?
  wait "$server_pid" || server_status=$?
  server_pid=''
  printf '{"server_exit":%s,"client_exit":%s,"route":"%s"}\n' "$server_status" "$client_status" "$route" > "$directory/result.json"
  test "$client_status" -eq 0 && test "$server_status" -eq 0
}
run_pair old-new "$baseline" off "$candidate" mixed priority
run_pair new-old "$candidate" mixed "$baseline" off seed
run_pair pq-seed "$candidate" pq-required "$candidate" pq-required seed
printf 'All three isolated process combinations passed.\n'

#!/bin/sh
# A local ZSA node for tests: QEDIT's Zebra (branch zsa1, the commit zcash_tx_tool's CI tests
# against) in Docker (rootless works), regtest with NU7/ZSA active from height 1, ephemeral state,
# JSON-RPC published on 127.0.0.1 only.
#
# usage: sh scripts/local-node.sh build|start|stop|status
#   ZSA_LOCAL_PORT   host port for the RPC (default 38232)
#   ZSA_ZEBRA_SRC    where to clone QEDIT's Zebra (default $HOME/zsa/src/zebra)
set -eu

ZEBRA_COMMIT=8c9c93fdd91b89fab387ec68362a93b2baca7bab
IMAGE=zsa-zebra:8c9c93fd
NAME=zsa-local-node
PORT="${ZSA_LOCAL_PORT:-38232}"
SRC="${ZSA_ZEBRA_SRC:-$HOME/zsa/src/zebra}"

rpc() {
  curl -s -m 5 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"1.0\",\"id\":\"x\",\"method\":\"$1\",\"params\":[]}" "http://127.0.0.1:$PORT"
}

case "${1:-}" in
  build)
    [ -d "$SRC" ] || git clone -q https://github.com/QED-it/zebra "$SRC"
    git -C "$SRC" fetch -q origin "$ZEBRA_COMMIT"
    git -C "$SRC" checkout -q "$ZEBRA_COMMIT"
    docker build -t "$IMAGE" --build-arg GIT_COMMIT="$ZEBRA_COMMIT" \
      -f "$SRC/testnet-single-node-deploy/dockerfile" "$SRC"
    ;;
  start)
    docker run -d --rm --name "$NAME" -p "127.0.0.1:$PORT:18232" "$IMAGE" >/dev/null
    i=0
    until rpc getblockcount | grep -q '"result"'; do
      i=$((i + 1))
      [ "$i" -le 60 ] || { echo "the node did not answer on 127.0.0.1:$PORT" >&2; exit 1; }
      sleep 1
    done
    echo "local ZSA node on http://127.0.0.1:$PORT (height $(rpc getblockcount | sed 's/.*"result":\([0-9]*\).*/\1/'))"
    ;;
  stop)
    docker stop "$NAME" >/dev/null && echo "stopped"
    ;;
  status)
    docker ps --filter "name=^$NAME\$" --format '{{.Names}} {{.Status}} {{.Ports}}'
    ;;
  *)
    echo "usage: sh scripts/local-node.sh build|start|stop|status" >&2
    exit 2
    ;;
esac

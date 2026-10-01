#!/bin/sh
# A local ZSA node for tests: QEDIT's Zebra (branch zsa1) in Docker (rootless works), regtest with
# NU7/ZSA active from height 1, ephemeral state, JSON-RPC published on 127.0.0.1 only.
#
# The pinned commit is the head of zsa1 that advertises the NU7 protocol version and keeps Regtest
# nodes running through NU7 activation. local-vectors and frost-selftest pass against it.
#
# usage: sh scripts/local-node.sh build|start|stop|status|version
#   ZSA_LOCAL_PORT     host port for the RPC (default 38232)
#   ZSA_ZEBRA_SRC      where to clone QEDIT's Zebra (default $HOME/zsa/src/zebra)
#   ZSA_ZEBRA_COMMIT   another zsa1 commit to build and run instead of the pinned one
set -eu

ZEBRA_COMMIT="${ZSA_ZEBRA_COMMIT:-05563cebde9fa0504876aae92ca6bbd1f62b5fac}"
IMAGE="zsa-zebra:$(printf %.8s "$ZEBRA_COMMIT")"
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
  version)
    printf '%s\n' "$(rpc getnetworkinfo | sed -n 's/.*"subversion":"\([^"]*\)".*"protocolversion":\([0-9]*\).*/\1 protocol \2/p')"
    ;;
  *)
    echo "usage: sh scripts/local-node.sh build|start|stop|status|version" >&2
    exit 2
    ;;
esac

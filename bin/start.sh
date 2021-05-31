#!/bin/bash

set -e

BUILD=false
RELEASE=false

function die_usage {
  echo "Usage: $(basename $0) [-bh]"
  echo ""
  echo "Options:"
  echo "  -h           Show this beautiful message"
  echo "  -b           Build the artifacts if they're missing"
  echo "  -r           Build in release mode"
  echo ""
  exit 1
}

while getopts "bhr" opt; do
  case $opt in
    b) BUILD=true ;;
    r) RELEASE=true ;;
    h) die_usage ;;
    \? ) die_usage
      ;;
  esac
done

if $BUILD || $RELEASE; then
  if $RELEASE; then
    (cd server; cargo build --release)
    cp server/target/release/server bin/server
    echo "built the server (release)"
  else
    (cd server; cargo build)
    cp server/target/debug/server bin/server
    echo "built the server"
  fi
fi

if [[ ! -f bin/server ]]; then
  echo "missing bin/server executable"
  exit 1
fi

(cd server/ && migrant setup)
(cd server/ && migrant list)
(cd server/ && migrant apply -a || true)

./bin/server

#!/bin/bash

set -euo pipefail

echo "building image: latest"

docker build -t slackat:latest .

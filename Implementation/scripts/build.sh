#!/usr/bin/env bash
# Compile the project (needs JDK 17+). Run from the Implementation folder:  ./scripts/build.sh
set -e
cd "$(dirname "$0")/.."
mkdir -p out
javac -d out $(find src -name "*.java")
echo "Build OK -> out/"

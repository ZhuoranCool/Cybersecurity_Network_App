#!/usr/bin/env bash
set -euo pipefail
rm -rf out
mkdir -p out data/as data/rs
javac -d out -cp "lib/*" $(find src/main src/org -name "*.java")
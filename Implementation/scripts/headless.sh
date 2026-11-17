#!/usr/bin/env bash
# Run the whole study without a GUI and write tables + charts to results/
cd "$(dirname "$0")/.."
java -cp "out:lib/*" com.threatprio.Main --headless "$@"

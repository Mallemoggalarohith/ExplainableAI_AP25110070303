#!/usr/bin/env bash
cd "$(dirname "$0")/.."
java -cp "out:lib/*" com.threatprio.SelfTest

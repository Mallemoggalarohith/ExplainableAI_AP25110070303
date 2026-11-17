#!/usr/bin/env bash
# Start the GUI.  If lib/sqlite-jdbc-*.jar exists it is used automatically (JDBC mode), otherwise CSV fallback.
cd "$(dirname "$0")/.."
java -cp "out:lib/*" com.threatprio.Main "$@"

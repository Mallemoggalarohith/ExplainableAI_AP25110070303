OPTIONAL - enables the JDBC/SQLite database mode.

Download this single jar into this folder (lib/):
  https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.41.2.2/sqlite-jdbc-3.41.2.2.jar

(3.41.2.2 is used because it has no extra dependencies.)
The scripts add lib/* to the classpath automatically. On start the GUI/CLI prints:
  "Storage: SQLite via JDBC (jdbc:sqlite:data/threatprio.db)"      <- jar found
  "Storage: CSV files in ... (JDBC driver not found)"              <- no jar, fallback mode
The program works in both modes. For the "Database Connectivity (JDBC)" section of the report, use JDBC mode.

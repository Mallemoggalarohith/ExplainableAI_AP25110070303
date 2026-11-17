"""Runs the exact SQL strings of JdbcThreatRepository.java against a real SQLite engine (python sqlite3)."""
import re, sqlite3, pathlib
src = pathlib.Path(__file__).resolve().parents[1].joinpath("src/com/threatprio/db/JdbcThreatRepository.java").read_text()
sql = {m.group(1): "".join(re.findall(r'"([^"]*)"', m.group(2)))
       for m in re.finditer(r'static final String (\w+) =\s*((?:"[^"]*"\s*\+?\s*)+);', src)}
db = sqlite3.connect(":memory:")
db.execute(sql["CREATE_FINDINGS"]); db.execute(sql["CREATE_FEEDBACK"])
db.execute(sql["INSERT_FINDING"], ["CVE-1","2024-01-01","2025-09-30",7.5,"NETWORK",0.1,1,0,1,0.8,"A-1","web-1","WEB_SERVER",4,1,0])
assert db.execute(sql["COUNT_FINDINGS"]).fetchone()[0] == 1
db.execute(sql["INSERT_FEEDBACK"], ["CVE-1",4,"good","2026-11-17T10:00"])
assert db.execute(sql["UPDATE_FEEDBACK"], [5,"better","2026-11-17T11:00","CVE-1"]).rowcount == 1
assert db.execute(sql["SELECT_FEEDBACK"], ["CVE-1"]).fetchone()[1] == 5
try: db.execute(sql["INSERT_FEEDBACK"], ["CVE-2",9,"x","t"]); raise SystemExit("CHECK constraint missing")
except sqlite3.IntegrityError: pass
assert db.execute(sql["DELETE_FEEDBACK"], ["CVE-1"]).rowcount == 1
print("All JDBC SQL statements are valid SQLite.")

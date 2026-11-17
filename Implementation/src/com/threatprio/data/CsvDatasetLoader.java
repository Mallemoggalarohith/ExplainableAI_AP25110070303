package com.threatprio.data;

import com.threatprio.exception.ThreatPrioException;
import com.threatprio.model.*;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.*;

/**
 * Builds findings from REAL public files: an NVD-derived CSV, the CISA KEV catalogue CSV and a FIRST EPSS CSV.
 * Asset context is still synthetic (seeded) because real asset inventories are private.
 *
 * Label construction (no leakage): features use only information available on the snapshot date
 * (KEV entries added on/before it; EPSS file should be the archive of that date); the label is
 * "added to KEV within windowDays AFTER the snapshot".
 */
public final class CsvDatasetLoader {
    private CsvDatasetLoader() {}

    public static List<Finding> load(Path nvdCsv, Path kevCsv, Path epssCsv, LocalDate snapshot, int windowDays, long seed)
            throws ThreatPrioException {
        Map<String, LocalDate> kevAdded = new HashMap<>();
        for (Map<String, String> r : CsvUtil.read(kevCsv)) {
            String id = r.getOrDefault("cveID", r.getOrDefault("cve_id", ""));
            String d = r.getOrDefault("dateAdded", "");
            if (!id.isEmpty() && !d.isEmpty()) kevAdded.put(id, LocalDate.parse(d));
        }
        Map<String, Double> epss = new HashMap<>();
        for (Map<String, String> r : CsvUtil.read(epssCsv)) {
            try { epss.put(r.get("cve"), Double.parseDouble(r.get("epss"))); } catch (RuntimeException ignored) { }
        }
        Random rnd = new Random(seed);
        List<Map<String, String>> nvd = CsvUtil.read(nvdCsv);
        List<Asset> pool = SyntheticDataGenerator.createAssetPool(Math.max(20, nvd.size() / 5), rnd);
        List<Finding> out = new ArrayList<>();
        for (Map<String, String> r : nvd) {
            try {
                String id = r.get("cve_id");
                LocalDate pub = LocalDate.parse(r.get("published").substring(0, 10));
                if (pub.isAfter(snapshot)) continue;
                double cvss = Double.parseDouble(r.get("cvss_base"));
                LocalDate added = kevAdded.get(id);
                boolean inKev = added != null && !added.isAfter(snapshot);
                boolean exploited = added != null && added.isAfter(snapshot) && !added.isAfter(snapshot.plusDays(windowDays));
                double e = epss.getOrDefault(id, 0.0);
                boolean exploitCode = "1".equals(r.get("exploit_code_public")) || "true".equalsIgnoreCase(r.get("exploit_code_public"));
                boolean patch = !"0".equals(r.get("patch_available")) && !"false".equalsIgnoreCase(r.get("patch_available"));
                double conf = Math.min(1.0, 0.5 + (inKev ? 0.25 : 0) + (epss.containsKey(id) ? 0.25 : 0));   // documented proxy
                Vulnerability v = new Vulnerability(id, pub, cvss, AttackVector.parse(r.get("attack_vector")),
                    Math.min(1.0, Math.max(0.0, e)), inKev, exploitCode, patch, conf);
                out.add(new Finding(v, pool.get(rnd.nextInt(pool.size())), snapshot, exploited));
            } catch (RuntimeException ex) {
                // skip malformed rows silently but keep going (counted by caller via size difference)
            }
        }
        if (out.isEmpty()) throw new ThreatPrioException("No usable rows after joining NVD, KEV and EPSS files");
        return out;
    }
}

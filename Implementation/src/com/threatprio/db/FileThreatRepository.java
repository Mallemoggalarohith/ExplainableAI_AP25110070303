package com.threatprio.db;

import com.threatprio.data.CsvUtil;
import com.threatprio.exception.ThreatPrioException;
import com.threatprio.model.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/** Fallback repository storing findings and feedback as CSV files; used when no JDBC driver is installed. */
public class FileThreatRepository implements ThreatRepository {
    private static final String HEADER = "cve_id,published,snapshot,cvss,attack_vector,epss,in_kev,exploit_code,patch,confidence,"
        + "asset_id,asset_name,asset_type,criticality,internet_facing,exploited";
    private final Path dir;
    private final Path findingsFile, feedbackFile;

    public FileThreatRepository(Path dir) {
        this.dir = dir;
        this.findingsFile = dir.resolve("findings.csv");
        this.feedbackFile = dir.resolve("analyst_feedback.csv");
    }

    @Override public String describe() { return "CSV files in " + dir.toAbsolutePath() + " (JDBC driver not found)"; }

    @Override public void init() throws ThreatPrioException {
        try { Files.createDirectories(dir); } catch (IOException e) { throw new ThreatPrioException("Cannot create " + dir, e); }
    }

    @Override public synchronized void replaceFindings(List<Finding> findings) throws ThreatPrioException {
        List<String> lines = new ArrayList<>();
        lines.add(HEADER);
        for (Finding f : findings) {
            Vulnerability v = f.getVulnerability(); Asset a = f.getAsset();
            lines.add(String.join(",", v.getId(), v.getPublished().toString(), f.getSnapshot().toString(), String.valueOf(v.getCvssBase()),
                v.getAttackVector().name(), String.valueOf(v.getEpss()), v.isInKev() ? "1" : "0", v.isExploitCodePublic() ? "1" : "0",
                v.isPatchAvailable() ? "1" : "0", String.valueOf(v.getIntelConfidence()), a.getId(), CsvUtil.quote(a.getName()),
                a.getType().name(), String.valueOf(a.getCriticality()), a.isInternetFacing() ? "1" : "0", String.valueOf(f.label())));
        }
        write(findingsFile, lines);
    }

    @Override public synchronized List<Finding> loadFindings() throws ThreatPrioException {
        if (!Files.exists(findingsFile)) return new ArrayList<>();
        List<Finding> out = new ArrayList<>();
        for (Map<String, String> r : CsvUtil.read(findingsFile)) {
            Vulnerability v = new Vulnerability(r.get("cve_id"), LocalDate.parse(r.get("published")), Double.parseDouble(r.get("cvss")),
                AttackVector.parse(r.get("attack_vector")), Double.parseDouble(r.get("epss")), "1".equals(r.get("in_kev")),
                "1".equals(r.get("exploit_code")), "1".equals(r.get("patch")), Double.parseDouble(r.get("confidence")));
            Asset a = new Asset(r.get("asset_id"), r.get("asset_name"), AssetType.parse(r.get("asset_type")),
                Integer.parseInt(r.get("criticality")), "1".equals(r.get("internet_facing")));
            out.add(new Finding(v, a, LocalDate.parse(r.get("snapshot")), "1".equals(r.get("exploited"))));
        }
        return out;
    }

    @Override public int countFindings() throws ThreatPrioException { return loadFindings().size(); }

    @Override public synchronized void clearFindings() throws ThreatPrioException {
        try { Files.deleteIfExists(findingsFile); } catch (IOException e) { throw new ThreatPrioException("Delete failed", e); }
    }

    private Map<String, AnalystFeedback> readFeedback() throws ThreatPrioException {
        Map<String, AnalystFeedback> m = new LinkedHashMap<>();
        if (!Files.exists(feedbackFile)) return m;
        for (Map<String, String> r : CsvUtil.read(feedbackFile))
            m.put(r.get("cve_id"), new AnalystFeedback(r.get("cve_id"), Integer.parseInt(r.get("rating")), r.get("comment"), LocalDateTime.parse(r.get("updated_at"))));
        return m;
    }

    private void writeFeedback(Map<String, AnalystFeedback> m) throws ThreatPrioException {
        List<String> lines = new ArrayList<>();
        lines.add("cve_id,rating,comment,updated_at");
        for (AnalystFeedback f : m.values())
            lines.add(f.cveId() + "," + f.rating() + "," + CsvUtil.quote(f.comment() == null ? "" : f.comment()) + "," + f.updatedAt());
        write(feedbackFile, lines);
    }

    @Override public synchronized void saveFeedback(AnalystFeedback fb) throws ThreatPrioException {
        Map<String, AnalystFeedback> m = readFeedback();
        m.put(fb.cveId(), fb);
        writeFeedback(m);
    }
    @Override public synchronized Optional<AnalystFeedback> findFeedback(String id) throws ThreatPrioException { return Optional.ofNullable(readFeedback().get(id)); }
    @Override public synchronized List<AnalystFeedback> allFeedback() throws ThreatPrioException {
        return readFeedback().values().stream().sorted(Comparator.comparing(AnalystFeedback::updatedAt).reversed()).collect(Collectors.toList());
    }
    @Override public synchronized boolean deleteFeedback(String id) throws ThreatPrioException {
        Map<String, AnalystFeedback> m = readFeedback();
        boolean removed = m.remove(id) != null;
        if (removed) writeFeedback(m);
        return removed;
    }

    private void write(Path f, List<String> lines) throws ThreatPrioException {
        try { Files.write(f, lines, StandardCharsets.UTF_8); } catch (IOException e) { throw new ThreatPrioException("Cannot write " + f, e); }
    }
}

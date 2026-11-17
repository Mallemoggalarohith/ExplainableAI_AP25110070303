package com.threatprio.gui;

import com.threatprio.data.*;
import com.threatprio.db.*;
import com.threatprio.eval.ExperimentRunner;
import com.threatprio.exception.ThreatPrioException;
import com.threatprio.model.Finding;
import com.threatprio.scoring.Scorer;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/** Holds application state and coordinates data, persistence, experiments and scoring (keeps the GUI thin). */
public class AppController {
    private final ThreatRepository repository;
    private List<Finding> findings = new ArrayList<>();
    private ExperimentRunner.Outcome outcome;
    private long seed = 42;

    public AppController(Path dataDir) throws ThreatPrioException {
        repository = RepositoryFactory.create(dataDir);
        repository.init();
        findings = repository.loadFindings();
    }

    public ThreatRepository repository() { return repository; }
    public List<Finding> findings() { return findings; }
    public ExperimentRunner.Outcome outcome() { return outcome; }
    public boolean hasResults() { return outcome != null; }

    public void generate(int n, long seed) throws ThreatPrioException {
        this.seed = seed;
        findings = SyntheticDataGenerator.generate(n, seed);
        repository.replaceFindings(findings);
        outcome = null;
    }

    public void loadFromRepository() throws ThreatPrioException {
        findings = repository.loadFindings();
        outcome = null;
    }

    public void loadRealFiles(Path nvd, Path kev, Path epss, LocalDate snapshot, int windowDays) throws ThreatPrioException {
        findings = CsvDatasetLoader.load(nvd, kev, epss, snapshot, windowDays, seed);
        repository.replaceFindings(findings);
        outcome = null;
    }

    public void runExperiment(Consumer<String> progress) throws Exception {
        outcome = new ExperimentRunner(seed, progress).run(findings);
    }

    public String summary() {
        if (findings.isEmpty()) return "No data loaded. Generate a synthetic dataset or load NVD/KEV/EPSS files.";
        List<Finding> u = DatasetSplit.deduplicate(findings);
        long kev = u.stream().filter(f -> f.getVulnerability().isInKev()).count();
        return String.format("Storage: %s%nFindings: %d (unique CVEs: %d)%nExploited in window: %.2f%%%nIn KEV at snapshot: %d%nInternet-facing assets: %.1f%%%nSnapshot date: %s%nPublication range: %s to %s",
            repository.describe(), findings.size(), u.size(), 100 * DatasetSplit.prevalence(u), kev,
            100.0 * u.stream().filter(f -> f.getAsset().isInternetFacing()).count() / u.size(), u.get(0).getSnapshot(),
            u.stream().map(f -> f.getVulnerability().getPublished()).min(Comparator.naturalOrder()).get(),
            u.stream().map(f -> f.getVulnerability().getPublished()).max(Comparator.naturalOrder()).get());
    }

    /** Scores every finding with the chosen model and returns them ranked by organisational risk (streams + generics). */
    public List<ScoredFinding> rank(String modelName, String splitFilter) {
        if (outcome == null) return List.of();
        Scorer s = outcome.scorers().get(modelName);
        Set<String> tr = ids(outcome.split().train()), va = ids(outcome.split().validation()), te = ids(outcome.split().test());
        List<Finding> pool = DatasetSplit.deduplicate(findings).stream().filter(f -> {
            String sp = splitOf(f, tr, va, te);
            return splitFilter.equals("All") || splitFilter.equalsIgnoreCase(sp);
        }).collect(Collectors.toList());
        pool.sort(Comparator.comparingDouble(s::priority).reversed());
        List<ScoredFinding> out = new ArrayList<>(pool.size());
        int rank = 1;
        for (Finding f : pool) out.add(new ScoredFinding(rank++, f, s.probability(f), s.priority(f), splitOf(f, tr, va, te)));
        return out;
    }

    private static Set<String> ids(List<Finding> l) { return l.stream().map(Finding::getCveId).collect(Collectors.toSet()); }
    private static String splitOf(Finding f, Set<String> tr, Set<String> va, Set<String> te) {
        return tr.contains(f.getCveId()) ? "Train" : va.contains(f.getCveId()) ? "Validation" : te.contains(f.getCveId()) ? "Test" : "-";
    }
}

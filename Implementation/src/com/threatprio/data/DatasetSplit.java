package com.threatprio.data;

import com.threatprio.model.Finding;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

/** Leakage-safe split: deduplicate by CVE first, then split by publication date (train < val < test). */
public record DatasetSplit(List<Finding> train, List<Finding> validation, List<Finding> test) {

    public static List<Finding> deduplicate(List<Finding> all) {
        Map<String, Finding> unique = new LinkedHashMap<>();
        for (Finding f : all) unique.putIfAbsent(f.getCveId(), f);
        return new ArrayList<>(unique.values());
    }

    public static DatasetSplit temporal(List<Finding> all, LocalDate validationStart, LocalDate testStart) {
        List<Finding> u = deduplicate(all);
        Map<Integer, List<Finding>> parts = u.stream().collect(Collectors.groupingBy(f -> {
            LocalDate d = f.getVulnerability().getPublished();
            return d.isBefore(validationStart) ? 0 : d.isBefore(testStart) ? 1 : 2;
        }));
        return new DatasetSplit(parts.getOrDefault(0, List.of()), parts.getOrDefault(1, List.of()), parts.getOrDefault(2, List.of()));
    }

    public static double prevalence(List<Finding> fs) {
        return fs.isEmpty() ? 0 : fs.stream().filter(Finding::isExploited).count() / (double) fs.size();
    }

    public String describe() {
        return String.format("train=%d (%.1f%% exploited), validation=%d (%.1f%%), test=%d (%.1f%%)",
            train.size(), 100 * prevalence(train), validation.size(), 100 * prevalence(validation),
            test.size(), 100 * prevalence(test));
    }
}

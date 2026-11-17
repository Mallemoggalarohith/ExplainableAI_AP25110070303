package com.threatprio.data;

import com.threatprio.exception.ThreatPrioException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Minimal RFC-4180 style CSV reader (quotes, commas inside quotes) returning rows as header->value maps. */
public final class CsvUtil {
    private CsvUtil() {}

    public static List<Map<String, String>> read(Path file) throws ThreatPrioException {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            lines.removeIf(l -> l.isBlank() || l.startsWith("#"));       // EPSS files start with a '#' comment line
            if (lines.isEmpty()) return List.of();
            List<String> header = split(lines.get(0));
            List<Map<String, String>> rows = new ArrayList<>();
            for (int i = 1; i < lines.size(); i++) {
                List<String> cells = split(lines.get(i));
                Map<String, String> row = new HashMap<>();
                for (int c = 0; c < header.size(); c++) row.put(header.get(c).trim(), c < cells.size() ? cells.get(c).trim() : "");
                rows.add(row);
            }
            return rows;
        } catch (IOException e) {
            throw new ThreatPrioException("Cannot read " + file, e);
        }
    }

    public static List<String> split(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '"') { if (q && i + 1 < line.length() && line.charAt(i + 1) == '"') { cur.append('"'); i++; } else q = !q; }
            else if (ch == ',' && !q) { out.add(cur.toString()); cur.setLength(0); }
            else cur.append(ch);
        }
        out.add(cur.toString());
        return out;
    }

    public static String quote(String s) {
        return (s.contains(",") || s.contains("\"") || s.contains("\n")) ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }
}

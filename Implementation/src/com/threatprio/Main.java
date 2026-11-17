package com.threatprio;

import com.threatprio.data.SyntheticDataGenerator;
import com.threatprio.eval.ExperimentRunner;
import com.threatprio.gui.*;
import java.nio.file.Path;
import java.util.List;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Entry point.
 *   (no args)                       -> Swing GUI
 *   --headless [--n 6000] [--seed 42] [--out results]   -> run the whole study and write results/ (no display needed)
 */
public class Main {
    public static void main(String[] args) throws Exception {
        List<String> a = List.of(args);
        Path dataDir = Path.of("data");
        if (a.contains("--headless")) {
            int n = Integer.parseInt(value(a, "--n", "6000"));
            long seed = Long.parseLong(value(a, "--seed", "42"));
            Path out = Path.of(value(a, "--out", "results"));
            System.setProperty("java.awt.headless", "true");
            AppController c = new AppController(dataDir);
            System.out.println("Storage: " + c.repository().describe());
            c.generate(n, seed);
            c.runExperiment(System.out::println);
            ResultsExporter.export(c.outcome(), out);
            System.out.println("Results written to " + out.toAbsolutePath());
            return;
        }
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) { }
        AppController ctrl = new AppController(dataDir);
        SwingUtilities.invokeLater(() -> new MainWindow(ctrl).setVisible(true));
    }

    private static String value(List<String> a, String key, String def) {
        int i = a.indexOf(key);
        return i >= 0 && i + 1 < a.size() ? a.get(i + 1) : def;
    }
}

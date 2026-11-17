package com.threatprio.gui;

import java.nio.file.Files;
import java.nio.file.Path;
import javax.swing.SwingUtilities;

/**
 * Renders every GUI tab to PNG without a display (reference images / smoke test of the Swing code).
 * For the final report, take REAL screenshots of the running application.
 * Usage: java -cp out com.threatprio.gui.GuiScreenshots [outputFolder]
 */
public class GuiScreenshots {
    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");
        Path out = Path.of(args.length > 0 ? args[0] : "results/gui");
        Files.createDirectories(out);
        AppController c = new AppController(Path.of("data"));
        c.generate(6000, 42);
        c.runExperiment(m -> { });
        final MainPanel[] holder = new MainPanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new MainPanel(c));
        MainPanel p = holder[0];
        String[] names = {"1_data", "2_prioritisation", "3_evaluation", "4_charts", "5_feedback"};
        for (int i = 0; i < names.length; i++) {
            final int idx = i;
            SwingUtilities.invokeAndWait(() -> {
                p.tabs().setSelectedIndex(idx);
                if (idx == 1) selectFirstRow(p);
                try { ResultsExporter.render(p, 1280, 780, out.resolve("gui_" + names[idx] + ".png").toFile()); }
                catch (Exception e) { throw new RuntimeException(e); }
            });
        }
        System.out.println("Screens written to " + out.toAbsolutePath());
    }

    private static void selectFirstRow(MainPanel p) {
        javax.swing.JTable t = find(p, javax.swing.JTable.class, "Rank");
        if (t != null && t.getRowCount() > 0) t.setRowSelectionInterval(0, 0);
    }

    private static <T extends java.awt.Component> T find(java.awt.Container c, Class<T> cls, String firstColumn) {
        for (java.awt.Component ch : c.getComponents()) {
            if (cls.isInstance(ch) && ch instanceof javax.swing.JTable t && t.getColumnName(0).equals(firstColumn)) return cls.cast(ch);
            if (ch instanceof java.awt.Container cc) { T r = find(cc, cls, firstColumn); if (r != null) return r; }
        }
        return null;
    }
}

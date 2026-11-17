package com.threatprio.gui;

import com.threatprio.eval.ExperimentResult;
import com.threatprio.eval.ExperimentRunner;
import com.threatprio.model.Finding;
import com.threatprio.scoring.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import javax.imageio.ImageIO;
import javax.swing.JComponent;

/** Writes markdown/CSV tables, chart PNGs and example explanations to a results folder (headless-safe). */
public final class ResultsExporter {
    private ResultsExporter() {}

    public static void export(ExperimentRunner.Outcome o, Path dir) throws IOException {
        Files.createDirectories(dir);
        ExperimentResult r = o.result();
        Files.writeString(dir.resolve("experiment_results.md"), r.toMarkdown(), StandardCharsets.UTF_8);

        StringBuilder csv = new StringBuilder("model,roc_auc,pr_auc,brier,ece,p50,p100,ndcg50,ndcg100\n");
        for (ExperimentResult.ModelMetrics m : r.metrics())
            csv.append(String.format("\"%s\",%.4f,%.4f,%s,%s,%.3f,%.3f,%.4f,%.4f%n", m.model(), m.rocAuc(), m.prAuc(),
                m.probabilistic() ? String.format("%.5f", m.brier()) : "", m.probabilistic() ? String.format("%.5f", m.ece()) : "",
                m.p50(), m.p100(), m.ndcg50(), m.ndcg100()));
        Files.writeString(dir.resolve("metrics.csv"), csv.toString(), StandardCharsets.UTF_8);

        Scorer gb = o.scorers().get("XGBoost-style GBDT + SHAP");
        List<Finding> test = o.split().test();
        List<Finding> top = test.stream().sorted((a, b) -> Double.compare(gb.priority(b), gb.priority(a))).limit(20).toList();
        StringBuilder tp = new StringBuilder("rank,cve,asset,criticality,cvss,epss,in_kev,p_exploit,risk,actually_exploited\n");
        int i = 1;
        for (Finding f : top)
            tp.append(String.format("%d,%s,%s,%d,%.1f,%.4f,%d,%.4f,%.4f,%d%n", i++, f.getCveId(), f.getAsset().getName(), f.getAsset().getCriticality(),
                f.getVulnerability().getCvssBase(), f.getVulnerability().getEpss(), f.getVulnerability().isInKev() ? 1 : 0,
                gb.probability(f), gb.priority(f), f.label()));
        Files.writeString(dir.resolve("top20_priorities_test_set.csv"), tp.toString(), StandardCharsets.UTF_8);

        StringBuilder ex = new StringBuilder("Example explanations for the 3 highest-risk test findings (GBDT + TreeSHAP)\n\n");
        for (Finding f : top.subList(0, 3))
            ex.append(f.getVulnerability().describe()).append(" on ").append(f.getAsset().describe()).append('\n')
              .append(((Explainable) gb).explain(f).toText(5)).append('\n');
        Files.writeString(dir.resolve("example_explanations.txt"), ex.toString(), StandardCharsets.UTF_8);

        System.setProperty("java.awt.headless", "true");
        save(ChartFactory.roc(r), dir.resolve("chart_roc.png"));
        save(ChartFactory.pr(r), dir.resolve("chart_pr.png"));
        save(ChartFactory.calibration(r), dir.resolve("chart_calibration.png"));
        save(ChartFactory.importance(r), dir.resolve("chart_importance.png"));
        save(ChartFactory.explanation(((Explainable) gb).explain(top.get(0)), "GBDT"), dir.resolve("chart_explanation_top1.png"));
    }

    /** Renders any Swing component to a PNG without a display (headless). */
    public static void save(JComponent c, Path file) throws IOException { render(c, 700, 480, file.toFile()); }

    public static void render(JComponent c, int w, int h, File file) throws IOException {
        c.setSize(w, h);
        layoutTree(c);
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(Color.WHITE); g.fillRect(0, 0, w, h);
        c.printAll(g);
        g.dispose();
        ImageIO.write(img, "png", file);
    }

    private static void layoutTree(Component c) {
        c.doLayout();
        if (c instanceof Container ct) for (Component ch : ct.getComponents()) layoutTree(ch);
    }
}

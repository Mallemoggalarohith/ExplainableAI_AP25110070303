package com.threatprio.gui;

import com.threatprio.db.AnalystFeedback;
import com.threatprio.eval.ExperimentResult;
import com.threatprio.model.Finding;
import com.threatprio.scoring.*;
import java.awt.*;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

/** All Swing screens in one panel (so it can also be rendered headlessly for documentation screenshots). */
public class MainPanel extends JPanel {
    private final AppController ctrl;
    private final JTabbedPane tabs = new JTabbedPane();

    // data tab
    private final JTextArea dataSummary = new JTextArea();
    private final JSpinner nSpinner = new JSpinner(new SpinnerNumberModel(6000, 500, 50000, 500));
    private final JSpinner seedSpinner = new JSpinner(new SpinnerNumberModel(42, 0, 99999, 1));
    private final JLabel status = new JLabel("Ready.");

    // prioritisation tab
    private final JComboBox<String> modelBox = new JComboBox<>();
    private final JComboBox<String> splitBox = new JComboBox<>(new String[]{"Test", "All", "Train", "Validation"});
    private final JTextField search = new JTextField(12);
    private final FindingTableModel tableModel = new FindingTableModel();
    private final JTable table = new JTable(tableModel);
    private final JPanel explanationHolder = new JPanel(new BorderLayout());
    { explanationHolder.setPreferredSize(new Dimension(400, 300)); }
    private final JTextArea explanationText = new JTextArea(6, 30);
    private final JSpinner ratingSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 5, 1));
    private final JTextField commentField = new JTextField(18);
    private final JLabel feedbackStatus = new JLabel(" ");

    // evaluation + charts + feedback tabs
    private final DefaultTableModel metricsModel = new DefaultTableModel(
        new String[]{"Model", "ROC-AUC", "PR-AUC", "Brier", "ECE", "P@50", "P@100", "NDCG@50", "NDCG@100"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTextArea evalText = new JTextArea();
    private final JPanel chartsGrid = new JPanel(new GridLayout(2, 2, 6, 6));
    private final DefaultTableModel feedbackModel = new DefaultTableModel(new String[]{"CVE", "Rating", "Comment", "Updated"}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JLabel feedbackSummary = new JLabel(" ");

    public MainPanel(AppController ctrl) {
        super(new BorderLayout());
        this.ctrl = ctrl;
        tabs.addTab("1. Data", buildDataTab());
        tabs.addTab("2. Prioritisation & Explanations", buildPriorityTab());
        tabs.addTab("3. Evaluation", buildEvalTab());
        tabs.addTab("4. Charts", chartsGrid);
        tabs.addTab("5. Analyst Feedback", buildFeedbackTab());
        add(tabs, BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        add(status, BorderLayout.SOUTH);
        refreshData();
        if (ctrl.hasResults()) refreshResults();
    }

    public JTabbedPane tabs() { return tabs; }

    // ----------------------------------------------------------------- Data tab
    private JPanel buildDataTab() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton gen = new JButton("Generate synthetic dataset"), load = new JButton("Load from database"), real = new JButton("Import NVD + KEV + EPSS files...");
        top.add(new JLabel("Findings:")); top.add(nSpinner); top.add(new JLabel("Seed:")); top.add(seedSpinner);
        top.add(gen); top.add(load); top.add(real);
        gen.addActionListener(e -> runBackground("Generating dataset...", () -> ctrl.generate((Integer) nSpinner.getValue(), ((Integer) seedSpinner.getValue()).longValue()), this::refreshData));
        load.addActionListener(e -> runBackground("Loading from database...", ctrl::loadFromRepository, this::refreshData));
        real.addActionListener(e -> importReal());
        dataSummary.setEditable(false);
        dataSummary.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(dataSummary), BorderLayout.CENTER);
        JTextArea note = new JTextArea("Note: exploitation probability is modelled from threat evidence and exposure; organisational impact comes only from asset "
            + "criticality. Priority = P(exploit) x impact. Synthetic data is for method development - it does not represent a real organisation.");
        note.setLineWrap(true); note.setWrapStyleWord(true); note.setEditable(false); note.setOpaque(false);
        p.add(note, BorderLayout.SOUTH);
        return p;
    }

    private void importReal() {
        JFileChooser fc = new JFileChooser(Path.of("..", "Dataset").toFile());
        Path[] f = new Path[3];
        String[] names = {"NVD-derived CSV (cve_id,published,cvss_base,attack_vector,...)", "CISA KEV CSV (known_exploited_vulnerabilities.csv)", "FIRST EPSS CSV (epss_scores-YYYY-MM-DD.csv)"};
        for (int i = 0; i < 3; i++) {
            fc.setDialogTitle("Select " + names[i]);
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            f[i] = fc.getSelectedFile().toPath();
        }
        String snap = JOptionPane.showInputDialog(this, "Snapshot date (YYYY-MM-DD). Features use data up to this date; label = added to KEV within 90 days after.", "2025-01-01");
        if (snap == null) return;
        runBackground("Importing real data...", () -> ctrl.loadRealFiles(f[0], f[1], f[2], LocalDate.parse(snap.trim()), 90), this::refreshData);
    }

    private void refreshData() {
        dataSummary.setText(ctrl.summary());
        tableModel.setRows(List.of());
        if (ctrl.hasResults()) refreshResults();
        else { metricsModel.setRowCount(0); evalText.setText(""); chartsGrid.removeAll(); chartsGrid.revalidate(); chartsGrid.repaint(); }
        refreshFeedback();
    }

    // ----------------------------------------------------------------- Prioritisation tab
    private JPanel buildPriorityTab() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        top.add(new JLabel("Model:")); top.add(modelBox); top.add(new JLabel("Split:")); top.add(splitBox);
        top.add(new JLabel("Filter (CVE / asset):")); top.add(search);
        p.add(top, BorderLayout.NORTH);
        modelBox.addActionListener(e -> reload());
        splitBox.addActionListener(e -> reload());
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { tableModel.filter(search.getText()); }
            public void removeUpdate(DocumentEvent e) { tableModel.filter(search.getText()); }
            public void changedUpdate(DocumentEvent e) { tableModel.filter(search.getText()); }
        });
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showExplanation(); });

        explanationText.setEditable(false);
        explanationText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel fb = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton save = new JButton("Save / update rating"), del = new JButton("Delete rating");
        fb.add(new JLabel("Usefulness (1-5):")); fb.add(ratingSpinner); fb.add(new JLabel("Comment:")); fb.add(commentField); fb.add(save); fb.add(del); fb.add(feedbackStatus);
        save.addActionListener(e -> saveFeedback());
        del.addActionListener(e -> deleteFeedback());
        JPanel right = new JPanel(new BorderLayout(4, 4));
        right.add(explanationHolder, BorderLayout.CENTER);
        JPanel south = new JPanel(new BorderLayout());
        south.add(new JScrollPane(explanationText), BorderLayout.CENTER);
        south.add(fb, BorderLayout.SOUTH);
        right.add(south, BorderLayout.SOUTH);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(table), right);
        int[] widths = {45, 105, 125, 40, 50, 55, 40, 80, 60, 75, 70};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.setRowHeight(20);
        split.setDividerLocation(760);
        split.setResizeWeight(0.6);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private void reload() {
        if (!ctrl.hasResults() || modelBox.getSelectedItem() == null) return;
        List<ScoredFinding> rows = ctrl.rank((String) modelBox.getSelectedItem(), (String) splitBox.getSelectedItem());
        tableModel.setRows(rows);
        tableModel.filter(search.getText());
        status.setText(rows.size() + " findings ranked by " + modelBox.getSelectedItem() + " (risk = probability x impact).");
    }

    private ScoredFinding selected() {
        int r = table.getSelectedRow();
        return r < 0 ? null : tableModel.at(table.convertRowIndexToModel(r));
    }

    private void showExplanation() {
        ScoredFinding sf = selected();
        explanationHolder.removeAll();
        if (sf == null) { explanationHolder.revalidate(); explanationHolder.repaint(); return; }
        Scorer chosen = ctrl.outcome().scorers().get((String) modelBox.getSelectedItem());
        Scorer used = chosen instanceof Explainable ? chosen : ctrl.outcome().scorers().get("XGBoost-style GBDT + SHAP");
        Explanation ex = ((Explainable) used).explain(sf.finding());
        explanationHolder.add(ChartFactory.explanation(ex, used.name()), BorderLayout.CENTER);
        Finding f = sf.finding();
        StringBuilder sb = new StringBuilder();
        sb.append(f.getVulnerability().describe()).append("\nAsset: ").append(f.getAsset().describe())
          .append(f.getAsset().isInternetFacing() ? ", internet-facing" : ", internal").append('\n');
        if (used != chosen) sb.append("(").append(chosen.name()).append(" is a fixed formula - showing the GBDT explanation instead.)\n");
        sb.append(String.format("Impact (criticality/5): %.2f   Risk = %.3f x %.2f = %.3f%n%n",
            ImpactModel.impact(f.getAsset()), ex.probability(), ImpactModel.impact(f.getAsset()), ex.probability() * ImpactModel.impact(f.getAsset())));
        sb.append(ex.toText(4)).append("\nObserved outcome (label): ").append(f.isExploited() ? "EXPLOITED" : "not exploited");
        explanationText.setText(sb.toString());
        explanationText.setCaretPosition(0);
        try {
            Optional<AnalystFeedback> fb = ctrl.repository().findFeedback(f.getCveId());
            fb.ifPresentOrElse(x -> { ratingSpinner.setValue(x.rating()); commentField.setText(x.comment()); feedbackStatus.setText("Saved rating loaded."); },
                () -> { commentField.setText(""); feedbackStatus.setText("No rating yet."); });
        } catch (Exception ex2) { feedbackStatus.setText("DB error: " + ex2.getMessage()); }
        explanationHolder.revalidate(); explanationHolder.repaint();
    }

    private void saveFeedback() {
        ScoredFinding sf = selected();
        if (sf == null) { feedbackStatus.setText("Select a finding first."); return; }
        try {
            ctrl.repository().saveFeedback(new AnalystFeedback(sf.finding().getCveId(), (Integer) ratingSpinner.getValue(), commentField.getText(), LocalDateTime.now()));
            feedbackStatus.setText("Saved."); refreshFeedback();
        } catch (Exception e) { feedbackStatus.setText("Error: " + e.getMessage()); }
    }

    private void deleteFeedback() {
        ScoredFinding sf = selected();
        if (sf == null) return;
        try {
            feedbackStatus.setText(ctrl.repository().deleteFeedback(sf.finding().getCveId()) ? "Deleted." : "Nothing to delete.");
            refreshFeedback();
        } catch (Exception e) { feedbackStatus.setText("Error: " + e.getMessage()); }
    }

    // ----------------------------------------------------------------- Evaluation tab
    private JPanel buildEvalTab() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        JButton run = new JButton("Run full experiment (train + evaluate)");
        run.addActionListener(e -> runBackground("Running experiment...", () -> ctrl.runExperiment(m -> SwingUtilities.invokeLater(() -> status.setText(m))), this::refreshResults));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(run);
        p.add(top, BorderLayout.NORTH);
        JTable t = new JTable(metricsModel);
        t.setRowHeight(22);
        evalText.setEditable(false);
        evalText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(t), new JScrollPane(evalText));
        sp.setResizeWeight(0.3);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private void refreshResults() {
        if (!ctrl.hasResults()) return;
        ExperimentResult r = ctrl.outcome().result();
        metricsModel.setRowCount(0);
        for (ExperimentResult.ModelMetrics m : r.metrics())
            metricsModel.addRow(new Object[]{m.model(), String.format("%.3f", m.rocAuc()), String.format("%.3f", m.prAuc()),
                m.probabilistic() ? String.format("%.4f", m.brier()) : "n/a", m.probabilistic() ? String.format("%.4f", m.ece()) : "n/a",
                String.format("%.2f", m.p50()), String.format("%.2f", m.p100()), String.format("%.3f", m.ndcg50()), String.format("%.3f", m.ndcg100())});
        evalText.setText(r.toMarkdown());
        evalText.setCaretPosition(0);
        chartsGrid.removeAll();
        chartsGrid.add(ChartFactory.roc(r)); chartsGrid.add(ChartFactory.pr(r));
        chartsGrid.add(ChartFactory.calibration(r)); chartsGrid.add(ChartFactory.importance(r));
        chartsGrid.revalidate(); chartsGrid.repaint();
        modelBox.removeAllItems();
        for (String n : ctrl.outcome().scorers().keySet()) modelBox.addItem(n);
        modelBox.setSelectedItem("XGBoost-style GBDT + SHAP");
        reload();
    }

    // ----------------------------------------------------------------- Feedback tab
    private JPanel buildFeedbackTab() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        JTable t = new JTable(feedbackModel);
        p.add(new JScrollPane(t), BorderLayout.CENTER);
        p.add(feedbackSummary, BorderLayout.SOUTH);
        return p;
    }

    private void refreshFeedback() {
        feedbackModel.setRowCount(0);
        try {
            List<AnalystFeedback> all = ctrl.repository().allFeedback();
            for (AnalystFeedback f : all) feedbackModel.addRow(new Object[]{f.cveId(), f.rating(), f.comment(), f.updatedAt().toString()});
            feedbackSummary.setText(all.isEmpty() ? "No analyst ratings stored yet." : String.format("%d ratings, mean usefulness %.2f / 5",
                all.size(), all.stream().mapToInt(AnalystFeedback::rating).average().orElse(0)));
        } catch (Exception e) { feedbackSummary.setText("DB error: " + e.getMessage()); }
    }

    // ----------------------------------------------------------------- background work (multithreading)
    @FunctionalInterface private interface Job { void run() throws Exception; }

    private void runBackground(String message, Job job, Runnable onDone) {
        status.setText(message);
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() throws Exception { job.run(); return null; }
            @Override protected void done() {
                try { get(); onDone.run(); status.setText("Done."); }
                catch (Exception e) {
                    Throwable c = e.getCause() != null ? e.getCause() : e;
                    status.setText("Error: " + c.getMessage());
                    JOptionPane.showMessageDialog(MainPanel.this, c.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    // ----------------------------------------------------------------- table model
    private static final class FindingTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Rank", "CVE", "Asset", "Crit", "CVSS", "EPSS", "KEV", "P(exploit)", "Risk", "Split", "Actual"};
        private List<ScoredFinding> all = List.of(), shown = List.of();
        void setRows(List<ScoredFinding> rows) { all = rows; shown = rows; fireTableDataChanged(); }
        void filter(String q) {
            String s = q == null ? "" : q.trim().toLowerCase();
            shown = s.isEmpty() ? all : all.stream().filter(r -> r.finding().getCveId().toLowerCase().contains(s)
                || r.finding().getAsset().getName().toLowerCase().contains(s)).collect(java.util.stream.Collectors.toList());
            fireTableDataChanged();
        }
        ScoredFinding at(int i) { return shown.get(i); }
        @Override public int getRowCount() { return shown.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return switch (c) { case 0, 3 -> Integer.class; case 4, 5, 7, 8 -> Double.class; default -> String.class; };
        }
        @Override public Object getValueAt(int r, int c) {
            ScoredFinding s = shown.get(r); Finding f = s.finding();
            return switch (c) {
                case 0 -> s.rank(); case 1 -> f.getCveId(); case 2 -> f.getAsset().getName(); case 3 -> f.getAsset().getCriticality();
                case 4 -> f.getVulnerability().getCvssBase(); case 5 -> f.getVulnerability().getEpss();
                case 6 -> f.getVulnerability().isInKev() ? "Yes" : ""; case 7 -> Math.round(s.probability() * 1000) / 1000.0;
                case 8 -> Math.round(s.risk() * 1000) / 1000.0; case 9 -> s.split(); default -> f.isExploited() ? "Exploited" : "";
            };
        }
    }
}

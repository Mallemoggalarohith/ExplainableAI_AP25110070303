package com.threatprio.gui;

import com.threatprio.eval.ExperimentResult;
import com.threatprio.eval.Metrics;
import com.threatprio.scoring.Explanation;
import java.util.List;
import java.util.Map;

/** Builds the standard charts from experiment results (shared by the GUI and the headless exporter). */
public final class ChartFactory {
    private ChartFactory() {}

    public static LineChartPanel roc(ExperimentResult r) {
        LineChartPanel p = new LineChartPanel("ROC curves (test set)", "False positive rate", "True positive rate").diagonal(true);
        r.rocCurves().forEach(p::add);
        return p;
    }

    public static LineChartPanel pr(ExperimentResult r) {
        LineChartPanel p = new LineChartPanel("Precision-Recall curves (test set)", "Recall", "Precision");
        r.prCurves().forEach(p::add);
        return p;
    }

    public static LineChartPanel calibration(ExperimentResult r) {
        double max = 0.05;
        for (List<Metrics.CalibrationBin> bins : r.calibration().values())
            for (Metrics.CalibrationBin b : bins) max = Math.max(max, Math.max(b.meanPredicted(), b.observedRate()));
        max = Math.min(1.0, Math.ceil(max * 10) / 10.0);
        LineChartPanel p = new LineChartPanel("Calibration (reliability) diagram", "Mean predicted probability", "Observed exploitation rate")
            .pointsOnly(true).diagonal(true).axisMax(max, max);
        for (Map.Entry<String, List<Metrics.CalibrationBin>> e : r.calibration().entrySet()) {
            List<Metrics.CalibrationBin> bins = e.getValue();
            double[][] xy = new double[2][bins.size()];
            for (int i = 0; i < bins.size(); i++) { xy[0][i] = bins.get(i).meanPredicted(); xy[1][i] = bins.get(i).observedRate(); }
            p.add(e.getKey(), xy);
        }
        return p;
    }

    public static BarChartPanel importance(ExperimentResult r) {
        int n = r.importance().size();
        String[] l = new String[n]; double[] v = new double[n];
        for (int i = 0; i < n; i++) { l[i] = r.importance().get(i).feature(); v[i] = r.importance().get(i).gbmMeanAbsShap(); }
        return new BarChartPanel("Global importance: mean |SHAP| (GBDT)", l, v, false);
    }

    public static BarChartPanel explanation(Explanation e, String model) {
        List<Explanation.FeatureContribution> top = e.top(9);
        String[] l = new String[top.size()]; double[] v = new double[top.size()];
        for (int i = 0; i < top.size(); i++) { l[i] = String.format("%s=%.2f", top.get(i).feature(), top.get(i).value()); v[i] = top.get(i).contribution(); }
        return new BarChartPanel("Why this score? (" + model + ", log-odds contributions)", l, v, true);
    }
}

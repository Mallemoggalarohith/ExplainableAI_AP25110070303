package com.threatprio.gui;

import java.awt.*;
import javax.swing.JPanel;

/** Horizontal bar chart supporting negative values (SHAP contributions) or positive-only (importance). */
public class BarChartPanel extends JPanel {
    private final String title;
    private final String[] labels;
    private final double[] values;
    private final boolean signed;

    public BarChartPanel(String title, String[] labels, double[] values, boolean signed) {
        this.title = title; this.labels = labels; this.values = values; this.signed = signed;
        setBackground(Color.WHITE);
        setPreferredSize(new Dimension(420, 320));
    }

    @Override protected void paintComponent(Graphics g0) {
        super.paintComponent(g0);
        Graphics2D g = (Graphics2D) g0.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setFont(getFont().deriveFont(Font.BOLD, 13f));
        g.setColor(Color.DARK_GRAY);
        g.drawString(title, 10, 20);
        g.setFont(getFont().deriveFont(11f));
        int n = labels.length, left = 140, right = 60, top = 34, rowH = Math.max(16, (getHeight() - top - 12) / Math.max(1, n));
        double max = 1e-9;
        for (double v : values) max = Math.max(max, Math.abs(v));
        int pw = getWidth() - left - right;
        int zero = signed ? left + pw / 2 : left;
        int half = signed ? pw / 2 : pw;
        for (int i = 0; i < n; i++) {
            int y = top + i * rowH, len = (int) (half * Math.abs(values[i]) / max);
            g.setColor(Color.DARK_GRAY);
            g.drawString(labels[i], 8, y + rowH / 2 + 4);
            g.setColor(values[i] >= 0 ? new Color(0xD55E00) : new Color(0x0072B2));
            int x = values[i] >= 0 ? zero : zero - len;
            g.fillRect(x, y + 3, Math.max(1, len), rowH - 6);
            g.setColor(Color.DARK_GRAY);
            String s = String.format("%+.2f", values[i]);
            if (!signed) s = String.format("%.2f", values[i]);
            g.drawString(s, values[i] >= 0 ? zero + len + 4 : Math.max(2, zero - len - 38), y + rowH / 2 + 4);
        }
        g.setColor(Color.GRAY);
        g.drawLine(zero, top, zero, top + n * rowH);
        g.dispose();
    }
}

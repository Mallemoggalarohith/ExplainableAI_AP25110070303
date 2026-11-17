package com.threatprio.gui;

import java.awt.*;
import java.awt.geom.Path2D;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.JPanel;

/** Lightweight multi-series line/point chart drawn with Java2D (ROC, PR and calibration plots). */
public class LineChartPanel extends JPanel {
    public static final Color[] PALETTE = {new Color(0x888888), new Color(0xE69F00), new Color(0x0072B2), new Color(0xD55E00), new Color(0x009E73)};
    private final String title, xLabel, yLabel;
    private final Map<String, double[][]> series = new LinkedHashMap<>();
    private boolean diagonal, pointsOnly;
    private double xMax = 1, yMax = 1;

    public LineChartPanel(String title, String xLabel, String yLabel) {
        this.title = title; this.xLabel = xLabel; this.yLabel = yLabel;
        setBackground(Color.WHITE);
        setPreferredSize(new Dimension(420, 320));
    }
    public LineChartPanel add(String name, double[][] xy) { series.put(name, xy); return this; }
    public LineChartPanel diagonal(boolean d) { diagonal = d; return this; }
    public LineChartPanel pointsOnly(boolean p) { pointsOnly = p; return this; }
    public LineChartPanel axisMax(double x, double y) { xMax = x; yMax = y; return this; }

    @Override protected void paintComponent(Graphics g0) {
        super.paintComponent(g0);
        Graphics2D g = (Graphics2D) g0.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth(), h = getHeight(), l = 55, r = 15, t = 34, b = 48;
        int pw = w - l - r, ph = h - t - b;
        g.setColor(Color.DARK_GRAY);
        g.setFont(getFont().deriveFont(Font.BOLD, 13f));
        g.drawString(title, l, 20);
        g.setFont(getFont().deriveFont(11f));
        g.setColor(new Color(0xE5E5E5));
        for (int i = 0; i <= 5; i++) {
            int gx = l + pw * i / 5, gy = t + ph * i / 5;
            g.drawLine(gx, t, gx, t + ph); g.drawLine(l, gy, l + pw, gy);
        }
        g.setColor(Color.DARK_GRAY);
        g.drawRect(l, t, pw, ph);
        for (int i = 0; i <= 5; i++) {
            g.drawString(String.format("%.1f", xMax * i / 5), l + pw * i / 5 - 8, t + ph + 15);
            g.drawString(String.format("%.1f", yMax * (5 - i) / 5), l - 30, t + ph * i / 5 + 4);
        }
        g.drawString(xLabel, l + pw / 2 - 30, h - 8);
        Graphics2D gr = (Graphics2D) g.create();
        gr.rotate(-Math.PI / 2, 14, t + ph / 2 + 30);
        gr.drawString(yLabel, 14, t + ph / 2 + 30);
        gr.dispose();
        if (diagonal) {
            g.setColor(new Color(0xBBBBBB));
            g.setStroke(new BasicStroke(1f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[]{5f, 4f}, 0f));
            g.drawLine(l, t + ph, l + pw, t);
            g.setStroke(new BasicStroke(1f));
        }
        int k = 0, ly = t + ph - 14 * series.size() - 2;
        for (Map.Entry<String, double[][]> e : series.entrySet()) {
            Color c = PALETTE[k++ % PALETTE.length];
            g.setColor(c);
            double[] xs = e.getValue()[0], ys = e.getValue()[1];
            if (pointsOnly) {
                g.setStroke(new BasicStroke(1.5f));
                int px = -1, py = -1;
                for (int i = 0; i < xs.length; i++) {
                    int x = l + (int) (pw * Math.min(1, xs[i] / xMax)), y = t + ph - (int) (ph * Math.min(1, ys[i] / yMax));
                    g.fillOval(x - 4, y - 4, 8, 8);
                    if (px >= 0) g.drawLine(px, py, x, y);
                    px = x; py = y;
                }
            } else {
                Path2D.Double p = new Path2D.Double();
                for (int i = 0; i < xs.length; i++) {
                    double x = l + pw * Math.min(1, xs[i] / xMax), y = t + ph - ph * Math.min(1, ys[i] / yMax);
                    if (i == 0) p.moveTo(x, y); else p.lineTo(x, y);
                }
                g.setStroke(new BasicStroke(2f));
                g.draw(p);
            }
            g.setStroke(new BasicStroke(1f));
            int lx = l + pw - 185;
            g.fillRect(lx - 14, ly - 8, 10, 10);
            g.setColor(Color.DARK_GRAY);
            String n = e.getKey().length() > 28 ? e.getKey().substring(0, 28) : e.getKey();
            g.drawString(n, lx, ly + 1);
            ly += 14;
        }
        g.dispose();
    }
}

package com.threatprio.gui;

import java.awt.Dimension;
import javax.swing.*;

/** Application frame: menu bar + the main panel. */
public class MainWindow extends JFrame {
    public MainWindow(AppController ctrl) {
        super("Explainable AI for Cyber Threat Prioritisation");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setContentPane(new MainPanel(ctrl));
        JMenuBar bar = new JMenuBar();
        JMenu file = new JMenu("File"), help = new JMenu("Help");
        JMenuItem exit = new JMenuItem("Exit"), about = new JMenuItem("About");
        exit.addActionListener(e -> dispose());
        about.addActionListener(e -> JOptionPane.showMessageDialog(this,
            "Explainable AI for Cyber Threat Prioritisation\nPure-Java GBDT + TreeSHAP, logistic regression, CVSS and rule baselines.\n"
          + "Risk = P(exploitation) x asset impact.", "About", JOptionPane.INFORMATION_MESSAGE));
        file.add(exit); help.add(about); bar.add(file); bar.add(help);
        setJMenuBar(bar);
        setPreferredSize(new Dimension(1280, 780));
        pack();
        setLocationRelativeTo(null);
    }
}

package com.threatprio.gui;

import com.threatprio.model.Finding;

/** Row shown in the prioritisation table. */
public record ScoredFinding(int rank, Finding finding, double probability, double risk, String split) {}

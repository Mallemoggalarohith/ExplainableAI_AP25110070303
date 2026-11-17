package com.threatprio.db;

import java.time.LocalDateTime;

/** Analyst usefulness rating (1..5) of the explanation shown for one finding. */
public record AnalystFeedback(String cveId, int rating, String comment, LocalDateTime updatedAt) {
    public AnalystFeedback {
        if (rating < 1 || rating > 5) throw new IllegalArgumentException("rating must be 1..5");
    }
}

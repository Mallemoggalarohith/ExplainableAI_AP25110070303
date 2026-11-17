package com.threatprio.db;

import com.threatprio.exception.ThreatPrioException;
import com.threatprio.model.Finding;
import java.util.List;
import java.util.Optional;

/** Persistence abstraction (DAO). Implementations: JDBC/SQLite and a file-based fallback. */
public interface ThreatRepository extends AutoCloseable {
    String describe();
    void init() throws ThreatPrioException;

    // findings: insert / retrieve / delete
    void replaceFindings(List<Finding> findings) throws ThreatPrioException;
    List<Finding> loadFindings() throws ThreatPrioException;
    int countFindings() throws ThreatPrioException;
    void clearFindings() throws ThreatPrioException;

    // analyst feedback: insert / update / retrieve / delete
    void saveFeedback(AnalystFeedback fb) throws ThreatPrioException;           // update if present, else insert
    Optional<AnalystFeedback> findFeedback(String cveId) throws ThreatPrioException;
    List<AnalystFeedback> allFeedback() throws ThreatPrioException;
    boolean deleteFeedback(String cveId) throws ThreatPrioException;

    @Override default void close() {}
}

package com.threatprio.db;

import com.threatprio.exception.ThreatPrioException;
import com.threatprio.model.*;
import java.sql.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * JDBC implementation (tested SQL dialect: SQLite). Needs the sqlite-jdbc jar on the classpath (see lib/README).
 * Uses PreparedStatements everywhere (no SQL injection) and a transaction for bulk inserts.
 */
public class JdbcThreatRepository implements ThreatRepository {
    public static final String DRIVER = "org.sqlite.JDBC";

    static final String CREATE_FINDINGS =
        "CREATE TABLE IF NOT EXISTS findings (cve_id TEXT PRIMARY KEY, published TEXT NOT NULL, snapshot TEXT NOT NULL, "
      + "cvss REAL, attack_vector TEXT, epss REAL, in_kev INTEGER, exploit_code INTEGER, patch INTEGER, confidence REAL, "
      + "asset_id TEXT, asset_name TEXT, asset_type TEXT, criticality INTEGER, internet_facing INTEGER, exploited INTEGER)";
    static final String CREATE_FEEDBACK =
        "CREATE TABLE IF NOT EXISTS analyst_feedback (cve_id TEXT PRIMARY KEY, rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), "
      + "comment TEXT, updated_at TEXT)";
    static final String INSERT_FINDING =
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    static final String SELECT_FINDINGS = "SELECT * FROM findings ORDER BY cve_id";
    static final String COUNT_FINDINGS = "SELECT COUNT(*) FROM findings";
    static final String DELETE_FINDINGS = "DELETE FROM findings";
    static final String UPDATE_FEEDBACK = "UPDATE analyst_feedback SET rating=?, comment=?, updated_at=? WHERE cve_id=?";
    static final String INSERT_FEEDBACK = "INSERT INTO analyst_feedback (cve_id, rating, comment, updated_at) VALUES (?,?,?,?)";
    static final String SELECT_FEEDBACK = "SELECT cve_id, rating, comment, updated_at FROM analyst_feedback WHERE cve_id=?";
    static final String SELECT_ALL_FEEDBACK = "SELECT cve_id, rating, comment, updated_at FROM analyst_feedback ORDER BY updated_at DESC";
    static final String DELETE_FEEDBACK = "DELETE FROM analyst_feedback WHERE cve_id=?";

    private final String url;

    public JdbcThreatRepository(String dbFile) { this.url = "jdbc:sqlite:" + dbFile; }

    public static boolean driverAvailable() {
        try { Class.forName(DRIVER); return true; } catch (ClassNotFoundException e) { return false; }
    }

    @Override public String describe() { return "SQLite via JDBC (" + url + ")"; }

    private Connection connect() throws SQLException { return DriverManager.getConnection(url); }

    @Override public void init() throws ThreatPrioException {
        try (Connection c = connect(); Statement st = c.createStatement()) {
            st.execute(CREATE_FINDINGS);
            st.execute(CREATE_FEEDBACK);
        } catch (SQLException e) { throw new ThreatPrioException("Database initialisation failed", e); }
    }

    @Override public void replaceFindings(List<Finding> findings) throws ThreatPrioException {
        try (Connection c = connect()) {
            c.setAutoCommit(false);
            try (Statement del = c.createStatement(); PreparedStatement ps = c.prepareStatement(INSERT_FINDING)) {
                del.executeUpdate(DELETE_FINDINGS);
                for (Finding f : findings) {
                    Vulnerability v = f.getVulnerability(); Asset a = f.getAsset();
                    int i = 1;
                    ps.setString(i++, v.getId()); ps.setString(i++, v.getPublished().toString()); ps.setString(i++, f.getSnapshot().toString());
                    ps.setDouble(i++, v.getCvssBase()); ps.setString(i++, v.getAttackVector().name()); ps.setDouble(i++, v.getEpss());
                    ps.setInt(i++, v.isInKev() ? 1 : 0); ps.setInt(i++, v.isExploitCodePublic() ? 1 : 0); ps.setInt(i++, v.isPatchAvailable() ? 1 : 0);
                    ps.setDouble(i++, v.getIntelConfidence());
                    ps.setString(i++, a.getId()); ps.setString(i++, a.getName()); ps.setString(i++, a.getType().name());
                    ps.setInt(i++, a.getCriticality()); ps.setInt(i++, a.isInternetFacing() ? 1 : 0); ps.setInt(i, f.label());
                    ps.addBatch();
                }
                ps.executeBatch();
                c.commit();
            } catch (SQLException e) { c.rollback(); throw e; }
        } catch (SQLException e) { throw new ThreatPrioException("Saving findings failed", e); }
    }

    @Override public List<Finding> loadFindings() throws ThreatPrioException {
        List<Finding> out = new ArrayList<>();
        try (Connection c = connect(); Statement st = c.createStatement(); ResultSet r = st.executeQuery(SELECT_FINDINGS)) {
            while (r.next()) {
                Vulnerability v = new Vulnerability(r.getString("cve_id"), LocalDate.parse(r.getString("published")), r.getDouble("cvss"),
                    AttackVector.parse(r.getString("attack_vector")), r.getDouble("epss"), r.getInt("in_kev") == 1,
                    r.getInt("exploit_code") == 1, r.getInt("patch") == 1, r.getDouble("confidence"));
                Asset a = new Asset(r.getString("asset_id"), r.getString("asset_name"), AssetType.parse(r.getString("asset_type")),
                    r.getInt("criticality"), r.getInt("internet_facing") == 1);
                out.add(new Finding(v, a, LocalDate.parse(r.getString("snapshot")), r.getInt("exploited") == 1));
            }
        } catch (SQLException e) { throw new ThreatPrioException("Loading findings failed", e); }
        return out;
    }

    @Override public int countFindings() throws ThreatPrioException {
        try (Connection c = connect(); Statement st = c.createStatement(); ResultSet r = st.executeQuery(COUNT_FINDINGS)) {
            return r.next() ? r.getInt(1) : 0;
        } catch (SQLException e) { throw new ThreatPrioException("Count failed", e); }
    }

    @Override public void clearFindings() throws ThreatPrioException {
        try (Connection c = connect(); Statement st = c.createStatement()) { st.executeUpdate(DELETE_FINDINGS); }
        catch (SQLException e) { throw new ThreatPrioException("Delete failed", e); }
    }

    @Override public void saveFeedback(AnalystFeedback fb) throws ThreatPrioException {
        try (Connection c = connect()) {
            int rows;
            try (PreparedStatement up = c.prepareStatement(UPDATE_FEEDBACK)) {
                up.setInt(1, fb.rating()); up.setString(2, fb.comment()); up.setString(3, fb.updatedAt().toString()); up.setString(4, fb.cveId());
                rows = up.executeUpdate();
            }
            if (rows == 0) try (PreparedStatement in = c.prepareStatement(INSERT_FEEDBACK)) {
                in.setString(1, fb.cveId()); in.setInt(2, fb.rating()); in.setString(3, fb.comment()); in.setString(4, fb.updatedAt().toString());
                in.executeUpdate();
            }
        } catch (SQLException e) { throw new ThreatPrioException("Saving feedback failed", e); }
    }

    private static AnalystFeedback map(ResultSet r) throws SQLException {
        return new AnalystFeedback(r.getString(1), r.getInt(2), r.getString(3), LocalDateTime.parse(r.getString(4)));
    }

    @Override public Optional<AnalystFeedback> findFeedback(String cveId) throws ThreatPrioException {
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(SELECT_FEEDBACK)) {
            ps.setString(1, cveId);
            try (ResultSet r = ps.executeQuery()) { return r.next() ? Optional.of(map(r)) : Optional.empty(); }
        } catch (SQLException e) { throw new ThreatPrioException("Reading feedback failed", e); }
    }

    @Override public List<AnalystFeedback> allFeedback() throws ThreatPrioException {
        List<AnalystFeedback> out = new ArrayList<>();
        try (Connection c = connect(); Statement st = c.createStatement(); ResultSet r = st.executeQuery(SELECT_ALL_FEEDBACK)) {
            while (r.next()) out.add(map(r));
        } catch (SQLException e) { throw new ThreatPrioException("Reading feedback failed", e); }
        return out;
    }

    @Override public boolean deleteFeedback(String cveId) throws ThreatPrioException {
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(DELETE_FEEDBACK)) {
            ps.setString(1, cveId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) { throw new ThreatPrioException("Deleting feedback failed", e); }
    }
}

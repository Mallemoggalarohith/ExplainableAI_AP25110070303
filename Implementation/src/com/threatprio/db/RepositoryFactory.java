package com.threatprio.db;

import java.nio.file.Path;

/** Factory: chooses SQLite/JDBC when the driver is on the classpath, otherwise the CSV file fallback. */
public final class RepositoryFactory {
    private RepositoryFactory() {}

    public static ThreatRepository create(Path dataDir) {
        if (JdbcThreatRepository.driverAvailable()) return new JdbcThreatRepository(dataDir.resolve("threatprio.db").toString());
        return new FileThreatRepository(dataDir);
    }
}

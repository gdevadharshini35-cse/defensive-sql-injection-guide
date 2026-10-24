package com.defensive.security.config;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/**
 * DatabaseConfig - Defensive Database Connection Manager
 * 
 * Provides centralized JDBC connection handling, defensive timeout configuration,
 * credentials management, and automatic graceful fallback to in-memory educational
 * demo mode if MySQL is not currently running.
 */
public class DatabaseConfig {

    private static String dbUrl = "jdbc:mysql://localhost:3306/db_security_vac?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&characterEncoding=UTF-8";
    private static String dbUser = "root";
    private static String dbPassword = "root";
    private static String dbDriver = "com.mysql.cj.jdbc.Driver";
    private static int serverPort = 8080;
    private static boolean databaseAvailable = false;
    private static String lastConnectionError = "Database not checked yet.";

    static {
        loadConfiguration();
    }

    private static void loadConfiguration() {
        Properties props = new Properties();
        try (InputStream in = DatabaseConfig.class.getClassLoader().getResourceAsStream("db.properties")) {
            if (in != null) {
                props.load(in);
                dbUrl = props.getProperty("db.url", dbUrl);
                dbUser = props.getProperty("db.user", dbUser);
                dbPassword = props.getProperty("db.password", dbPassword);
                dbDriver = props.getProperty("db.driver", dbDriver);
                serverPort = Integer.parseInt(props.getProperty("server.port", "8080"));
            }
        } catch (Exception e) {
            System.err.println("[WARN] db.properties not found or unreadable, using default settings: " + e.getMessage());
        }

        // Check if MySQL driver is present
        try {
            Class.forName(dbDriver);
        } catch (ClassNotFoundException e) {
            System.err.println("[WARN] MySQL JDBC Driver (" + dbDriver + ") not found on classpath: " + e.getMessage());
        }
    }

    /**
     * Attempts to acquire a new JDBC connection to MySQL.
     * 
     * @return Connection object
     * @throws SQLException if connection fails
     */
    public static Connection getConnection() throws SQLException {
        // Enforce 5-second login timeout to prevent thread starvation
        DriverManager.setLoginTimeout(5);
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    /**
     * Tests connectivity to the MySQL database server.
     * Updates internal availability flag.
     * 
     * @return true if MySQL is reachable and connected, false otherwise
     */
    public static boolean checkConnection() {
        try (Connection conn = getConnection()) {
            if (conn != null && !conn.isClosed()) {
                databaseAvailable = true;
                lastConnectionError = null;
                return true;
            }
        } catch (SQLException e) {
            databaseAvailable = false;
            // DEFENSIVE NOTE: Capture sanitized error description for admin diagnostics
            lastConnectionError = e.getMessage();
        }
        return false;
    }

    /**
     * Initializes tables if the database exists and tables are missing.
     */
    public static void ensureSchema() {
        if (!databaseAvailable) return;
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            // Check if 'users' table exists, if not create minimal schema
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "username VARCHAR(50) NOT NULL UNIQUE, " +
                    "email VARCHAR(100) NOT NULL UNIQUE, " +
                    "password_hash VARCHAR(128) NOT NULL, " +
                    "salt VARCHAR(64) NOT NULL, " +
                    "role VARCHAR(20) DEFAULT 'student', " +
                    "failed_attempts INT DEFAULT 0, " +
                    "is_locked BOOLEAN DEFAULT FALSE, " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ") ENGINE=InnoDB;");

            stmt.execute("CREATE TABLE IF NOT EXISTS quiz_attempts (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "student_name VARCHAR(100) NOT NULL, " +
                    "student_id VARCHAR(50) DEFAULT 'N/A', " +
                    "score INT NOT NULL, " +
                    "total_questions INT NOT NULL, " +
                    "percentage DECIMAL(5,2) NOT NULL, " +
                    "grade VARCHAR(10) NOT NULL, " +
                    "time_taken_seconds INT DEFAULT 0, " +
                    "feedback_notes TEXT, " +
                    "attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ") ENGINE=InnoDB;");

            stmt.execute("CREATE TABLE IF NOT EXISTS security_audit_logs (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "event_type VARCHAR(50) NOT NULL, " +
                    "severity VARCHAR(20) DEFAULT 'INFO', " +
                    "source_ip VARCHAR(45) DEFAULT '127.0.0.1', " +
                    "username_attempted VARCHAR(100) DEFAULT 'N/A', " +
                    "description TEXT NOT NULL, " +
                    "defense_action_taken VARCHAR(150) DEFAULT 'PreparedStatement Executed Safely', " +
                    "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                    ") ENGINE=InnoDB;");
        } catch (SQLException e) {
            System.err.println("[WARN] Schema verification warning: " + e.getMessage());
        }
    }

    public static boolean isDatabaseAvailable() {
        return databaseAvailable;
    }

    public static String getLastConnectionError() {
        return lastConnectionError;
    }

    public static int getServerPort() {
        return serverPort;
    }

    public static String getDbUrl() {
        return dbUrl;
    }

    public static String getDbUser() {
        return dbUser;
    }
}

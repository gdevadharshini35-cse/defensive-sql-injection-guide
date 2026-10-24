package com.defensive.security.dao;

import com.defensive.security.config.DatabaseConfig;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * AuditDAO - Defensive Security Audit Logging DAO
 * 
 * DEFENSIVE PRACTICE:
 * Comprehensive security logging and auditing is essential for detecting,
 * tracing, and analyzing injection attacks and malicious probes.
 * 
 * All audit records are written using PreparedStatement, guaranteeing that
 * attack payloads (e.g. `' OR '1'='1`) logged in the database NEVER trigger
 * Second-Order SQL Injection when viewed later!
 */
public class AuditDAO {

    private static final List<Map<String, Object>> IN_MEMORY_LOGS = new ArrayList<>();

    static {
        // Pre-populate sample defensive audit logs
        addMemoryLog("SYSTEM_START", "INFO", "127.0.0.1", "SYSTEM",
                "Application started. Defensive PreparedStatement engine active.", "PreparedStatement Enforced");
        addMemoryLog("SQLI_SIMULATION", "MEDIUM", "127.0.0.1", "student_demo",
                "Simulated bypass test with payload: ' OR '1'='1", "Safely handled as literal string parameter");
        addMemoryLog("LOGIN_SUCCESS", "INFO", "127.0.0.1", "student_alice",
                "Authentication verified using salted PBKDF2 hash match.", "Secure password verification complete");
    }

    private static void addMemoryLog(String eventType, String severity, String ip, String user, String desc, String action) {
        Map<String, Object> log = new LinkedHashMap<>();
        log.put("event_type", eventType);
        log.put("severity", severity);
        log.put("source_ip", ip);
        log.put("username_attempted", user);
        log.put("description", desc);
        log.put("defense_action_taken", action);
        log.put("created_at", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        IN_MEMORY_LOGS.add(0, log);
    }

    /**
     * Records a security event to MySQL using PreparedStatement.
     */
    public boolean logSecurityEvent(String eventType, String severity, String sourceIp, 
                                    String username, String description, String defenseAction) {

        addMemoryLog(eventType, severity, sourceIp, username, description, defenseAction);

        if (!DatabaseConfig.isDatabaseAvailable()) {
            return true;
        }

        String sql = "INSERT INTO security_audit_logs " +
                     "(event_type, severity, source_ip, username_attempted, description, defense_action_taken) " +
                     "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, eventType);
            ps.setString(2, severity);
            ps.setString(3, sourceIp);
            ps.setString(4, username);
            ps.setString(5, description);
            ps.setString(6, defenseAction);

            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("[SEC_AUDIT] Failed to persist audit log to MySQL: " + e.getMessage());
            return false;
        }
    }

    /**
     * Retrieves recent security audit logs for display in the admin/monitoring panel.
     */
    public List<Map<String, Object>> getRecentLogs(int limit) {
        List<Map<String, Object>> list = new ArrayList<>();

        if (!DatabaseConfig.isDatabaseAvailable()) {
            int count = Math.min(limit, IN_MEMORY_LOGS.size());
            for (int i = 0; i < count; i++) {
                list.add(IN_MEMORY_LOGS.get(i));
            }
            return list;
        }

        String sql = "SELECT event_type, severity, source_ip, username_attempted, description, defense_action_taken, created_at " +
                     "FROM security_audit_logs ORDER BY created_at DESC LIMIT ?";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, limit);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("event_type", rs.getString("event_type"));
                    row.put("severity", rs.getString("severity"));
                    row.put("source_ip", rs.getString("source_ip"));
                    row.put("username_attempted", rs.getString("username_attempted"));
                    row.put("description", rs.getString("description"));
                    row.put("defense_action_taken", rs.getString("defense_action_taken"));
                    row.put("created_at", rs.getString("created_at"));
                    list.add(row);
                }
            }
        } catch (SQLException e) {
            System.err.println("[SEC_AUDIT] Failed to read audit logs from MySQL: " + e.getMessage());
            return IN_MEMORY_LOGS;
        }

        return list;
    }
}

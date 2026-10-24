package com.defensive.security.dao;

import com.defensive.security.config.DatabaseConfig;
import com.defensive.security.util.PasswordUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * UserDAO - Secure Data Access Object for User Authentication
 * 
 * DEFENSIVE SECURITY DEMONSTRATION:
 * 
 * ❌ INSECURE PATTERN (DO NOT USE):
 *    String query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
 *    Statement stmt = conn.createStatement();
 *    ResultSet rs = stmt.executeQuery(query);
 *    --> Attacker inputs: ' OR '1'='1 -- 
 *    --> Resulting SQL: SELECT * FROM users WHERE username = '' OR '1'='1 -- ' AND ...
 *    --> Authentication bypassed!
 * 
 * ✅ SECURE DEFENSIVE PATTERN (PREPAREDSTATEMENT):
 *    String query = "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?";
 *    PreparedStatement ps = conn.prepareStatement(query);
 *    ps.setString(1, user);
 *    --> The database compiles the SQL structure FIRST.
 *    --> User input is treated strictly as literal string DATA, impossible to alter SQL logic.
 */
public class UserDAO {

    // Fallback demo users when MySQL server is not connected
    private static final Map<String, DemoUser> IN_MEMORY_USERS = new HashMap<>();

    static {
        // Alice: Password@123
        String saltAlice = "3f8a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a";
        String hashAlice = PasswordUtil.hashPassword("Password@123", saltAlice);
        IN_MEMORY_USERS.put("student_alice", new DemoUser(1, "student_alice", "alice@college.edu", hashAlice, saltAlice, "student"));

        // Bob: Student#2026
        String saltBob = "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b";
        String hashBob = PasswordUtil.hashPassword("Student#2026", saltBob);
        IN_MEMORY_USERS.put("student_bob", new DemoUser(2, "student_bob", "bob@college.edu", hashBob, saltBob, "student"));

        // Admin: Admin#Secure99!
        String saltAdmin = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";
        String hashAdmin = PasswordUtil.hashPassword("Admin#Secure99!", saltAdmin);
        IN_MEMORY_USERS.put("sec_admin", new DemoUser(3, "sec_admin", "admin@college.edu", hashAdmin, saltAdmin, "admin"));
    }

    public static class AuthResult {
        public final boolean success;
        public final String message;
        public final String role;
        public final String username;
        public final String queryExecuted;
        public final String defenseExplanation;

        public AuthResult(boolean success, String message, String role, String username, String queryExecuted, String defenseExplanation) {
            this.success = success;
            this.message = message;
            this.role = role;
            this.username = username;
            this.queryExecuted = queryExecuted;
            this.defenseExplanation = defenseExplanation;
        }
    }

    /**
     * Executes a DEFENSIVE authentication verification using PreparedStatement
     * and salted PBKDF2 hash checking.
     * 
     * @param username Input username
     * @param password Input plain-text password
     * @return AuthResult object with details
     */
    public AuthResult authenticateDefensively(String username, String password) {
        String parameterizedSql = "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?";
        String explanation = "PreparedStatement separated query command from parameter data. " +
                "Even payloads like \"' OR '1'='1\" were treated as an innocuous literal string.";

        if (!DatabaseConfig.isDatabaseAvailable()) {
            // Safe in-memory evaluation
            DemoUser user = IN_MEMORY_USERS.get(username);
            if (user != null && PasswordUtil.verifyPassword(password, user.passwordHash, user.salt)) {
                return new AuthResult(true, "Authentication successful (Safe Demo Mode)", user.role, user.username,
                        parameterizedSql + " [param1=" + username + "]", explanation);
            }
            return new AuthResult(false, "Invalid credentials. Authentication failed safely.", null, username,
                    parameterizedSql + " [param1=" + username + "]", explanation);
        }

        // Live MySQL database execution using PreparedStatement
        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(parameterizedSql)) {

            // Bind username parameter securely
            ps.setString(1, username);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String storedHash = rs.getString("password_hash");
                    String storedSalt = rs.getString("salt");
                    String role = rs.getString("role");

                    // Verify salted PBKDF2 hash
                    if (PasswordUtil.verifyPassword(password, storedHash, storedSalt)) {
                        return new AuthResult(true, "Authentication successful (Live MySQL)", role, username,
                                parameterizedSql + " [Bound: " + username + "]", explanation);
                    }
                }
            }
        } catch (SQLException e) {
            // DEFENSIVE ERROR HANDLING: Do not leak SQL exception message to client
            System.err.println("[SEC_AUDIT] Database query error: " + e.getMessage());
            return new AuthResult(false, "System error during authentication. Check server logs.", null, username,
                    parameterizedSql, "Query failed safely without leaking database internal structures.");
        }

        return new AuthResult(false, "Invalid credentials. Authentication rejected.", null, username,
                parameterizedSql + " [Bound: " + username + "]", explanation);
    }

    private static class DemoUser {
        final int id;
        final String username;
        final String email;
        final String passwordHash;
        final String salt;
        final String role;

        DemoUser(int id, String username, String email, String passwordHash, String salt, String role) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.role = role;
        }
    }
}

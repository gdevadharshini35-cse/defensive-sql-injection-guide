package com.defensive.security.dao;

import com.defensive.security.config.DatabaseConfig;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * QuizDAO - Secure Data Access Object for Quiz Results and Leaderboard
 * 
 * Demonstrates:
 *  - JDBC PreparedStatement for all INSERT and SELECT operations
 *  - Parameter binding with setString(), setInt(), setDouble()
 *  - Resource management with try-with-resources
 *  - Defense against SQL injection on user-submitted student names and notes
 */
public class QuizDAO {

    // In-memory fallback storage when MySQL is not running
    private static final List<Map<String, Object>> IN_MEMORY_ATTEMPTS = new ArrayList<>();

    static {
        // Pre-populate sample student quiz records
        Map<String, Object> a1 = new LinkedHashMap<>();
        a1.put("student_name", "Rohan Sharma");
        a1.put("student_id", "VAC-CYBER-001");
        a1.put("score", 9);
        a1.put("total_questions", 10);
        a1.put("percentage", 90.0);
        a1.put("grade", "A+");
        a1.put("time_taken_seconds", 145);
        a1.put("attempted_at", "2026-10-24 10:15:00");
        IN_MEMORY_ATTEMPTS.add(a1);

        Map<String, Object> a2 = new LinkedHashMap<>();
        a2.put("student_name", "Priya Patel");
        a2.put("student_id", "VAC-CYBER-002");
        a2.put("score", 10);
        a2.put("total_questions", 10);
        a2.put("percentage", 100.0);
        a2.put("grade", "A+");
        a2.put("time_taken_seconds", 120);
        a2.put("attempted_at", "2026-10-24 11:30:00");
        IN_MEMORY_ATTEMPTS.add(a2);

        Map<String, Object> a3 = new LinkedHashMap<>();
        a3.put("student_name", "Alex Chen");
        a3.put("student_id", "VAC-CYBER-003");
        a3.put("score", 8);
        a3.put("total_questions", 10);
        a3.put("percentage", 80.0);
        a3.put("grade", "A");
        a3.put("time_taken_seconds", 160);
        a3.put("attempted_at", "2026-10-24 13:45:00");
        IN_MEMORY_ATTEMPTS.add(a3);
    }

    /**
     * Saves a quiz attempt using secure PreparedStatement.
     */
    public boolean saveAttempt(String studentName, String studentId, int score, int total, 
                               double percentage, String grade, int timeSeconds, String feedback) {

        String sql = "INSERT INTO quiz_attempts " +
                     "(student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, feedback_notes) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        // Also add to in-memory list
        Map<String, Object> memoryRecord = new LinkedHashMap<>();
        memoryRecord.put("student_name", studentName);
        memoryRecord.put("student_id", studentId);
        memoryRecord.put("score", score);
        memoryRecord.put("total_questions", total);
        memoryRecord.put("percentage", percentage);
        memoryRecord.put("grade", grade);
        memoryRecord.put("time_taken_seconds", timeSeconds);
        memoryRecord.put("attempted_at", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        IN_MEMORY_ATTEMPTS.add(0, memoryRecord);

        if (!DatabaseConfig.isDatabaseAvailable()) {
            return true;
        }

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            // Bind all parameters using strong typing
            ps.setString(1, studentName);
            ps.setString(2, studentId);
            ps.setInt(3, score);
            ps.setInt(4, total);
            ps.setDouble(5, percentage);
            ps.setString(6, grade);
            ps.setInt(7, timeSeconds);
            ps.setString(8, feedback);

            int rowsAffected = ps.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            System.err.println("[SEC_AUDIT] Error recording quiz attempt: " + e.getMessage());
            return false;
        }
    }

    /**
     * Retrieves recent quiz attempts for the college leaderboard.
     */
    public List<Map<String, Object>> getRecentAttempts(int limit) {
        List<Map<String, Object>> list = new ArrayList<>();

        if (!DatabaseConfig.isDatabaseAvailable()) {
            int count = Math.min(limit, IN_MEMORY_ATTEMPTS.size());
            for (int i = 0; i < count; i++) {
                list.add(IN_MEMORY_ATTEMPTS.get(i));
            }
            return list;
        }

        String sql = "SELECT student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, attempted_at " +
                     "FROM quiz_attempts ORDER BY attempted_at DESC LIMIT ?";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, limit);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("student_name", rs.getString("student_name"));
                    row.put("student_id", rs.getString("student_id"));
                    row.put("score", rs.getInt("score"));
                    row.put("total_questions", rs.getInt("total_questions"));
                    row.put("percentage", rs.getDouble("percentage"));
                    row.put("grade", rs.getString("grade"));
                    row.put("time_taken_seconds", rs.getInt("time_taken_seconds"));
                    row.put("attempted_at", rs.getString("attempted_at"));
                    list.add(row);
                }
            }
        } catch (SQLException e) {
            System.err.println("[SEC_AUDIT] Error fetching quiz attempts: " + e.getMessage());
            // Fallback to in-memory list on query error
            return IN_MEMORY_ATTEMPTS;
        }

        return list;
    }
}

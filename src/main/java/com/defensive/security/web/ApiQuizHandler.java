package com.defensive.security.web;

import com.defensive.security.dao.AuditDAO;
import com.defensive.security.dao.QuizDAO;
import com.defensive.security.util.InputValidator;
import com.defensive.security.util.JsonHelper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * ApiQuizHandler - Handles Quiz Submissions and Leaderboard Retrieval
 * Endpoint: /api/quiz
 *  - GET: Retrieves recent quiz attempts from MySQL/In-memory
 *  - POST: Grades student answers, records score using PreparedStatement, returns feedback
 */
public class ApiQuizHandler implements HttpHandler {

    private final QuizDAO quizDAO = new QuizDAO();
    private final AuditDAO auditDAO = new AuditDAO();

    // Educational quiz master answer key with in-depth defense explanations
    private static final Map<Integer, QuestionMeta> QUESTIONS = new LinkedHashMap<>();

    static {
        QUESTIONS.put(1, new QuestionMeta(
                "What is the primary root cause of SQL Injection vulnerabilities?",
                "Concatenating untrusted user input directly into SQL command strings",
                "SQL Injection occurs when user-supplied input is directly concatenated into SQL queries. The SQL engine cannot distinguish where the developer's instructions end and the user's data begins."
        ));
        QUESTIONS.put(2, new QuestionMeta(
                "Why does a PreparedStatement effectively eliminate SQL Injection?",
                "The database compiles query structure beforehand and treats user input strictly as literal data",
                "PreparedStatement compiles the SQL statement into an execution plan first. When parameters are bound with ? markers, the database driver passes values strictly as data, never as executable SQL code."
        ));
        QUESTIONS.put(3, new QuestionMeta(
                "Which symbol is used as a parameter placeholder in JDBC PreparedStatements?",
                "Question mark (?)",
                "Standard JDBC uses the question mark (?) as the parameter marker, which is bound via methods like ps.setString(1, val)."
        ));
        QUESTIONS.put(4, new QuestionMeta(
                "Why is client-side JavaScript validation insufficient on its own for security?",
                "Attackers can easily bypass browser validation using proxy tools, cURL, or scripts",
                "Client-side validation exists for user experience, but can be trivially bypassed by sending HTTP requests directly. Server-side validation is non-negotiable."
        ));
        QUESTIONS.put(5, new QuestionMeta(
                "Why should database error messages never be displayed directly to web application users?",
                "They reveal database table names, column structures, and SQL syntax to attackers",
                "Detailed database errors (Error-based SQLi) leak sensitive architectural details to attackers. Applications should log errors internally and show a generic error message to users."
        ));
        QUESTIONS.put(6, new QuestionMeta(
                "What does the Principle of Least Privilege (PoLP) dictate for database accounts?",
                "The web app database user should only have permissions strictly necessary for its tasks (e.g. SELECT, INSERT, UPDATE)",
                "If an attacker breaches a query, least privilege limits the blast radius. A restricted web app account should never have DROP, ALTER, GRANT, or FILE permissions."
        ));
        QUESTIONS.put(7, new QuestionMeta(
                "Why should passwords NEVER be stored using plain MD5 or SHA-1 hashes?",
                "They are fast to compute and highly susceptible to precomputed Rainbow Table and GPU brute-force attacks",
                "MD5 and SHA-1 are cryptographically broken for passwords. Modern applications must use salted, adaptive key-derivation algorithms like PBKDF2, BCrypt, or Argon2id."
        ));
        QUESTIONS.put(8, new QuestionMeta(
                "What is the purpose of adding a unique 'Salt' to each password before hashing?",
                "It ensures that identical passwords produce completely unique hashes, preventing Rainbow Table attacks",
                "A cryptographic salt ensures two users with the exact same password have totally different stored hashes, rendering precomputed lookup tables completely useless."
        ));
        QUESTIONS.put(9, new QuestionMeta(
                "Which type of SQL Injection relies on observing database response delays (e.g. SLEEP)?",
                "Time-Based Blind SQL Injection",
                "When the application does not return data or errors, attackers inject sleep/delay commands to infer whether a boolean condition is true based on server response latency."
        ));
        QUESTIONS.put(10, new QuestionMeta(
                "Can PreparedStatements parameterize dynamic SQL table names or column names?",
                "No, table and column identifiers cannot be parameterized and must be validated against a strict whitelist",
                "PreparedStatements only parameterize values (data literals). Dynamic column or table names must be strictly validated against a hardcoded whitelist of allowed identifier strings."
        ));
    }

    private static class QuestionMeta {
        final String question;
        final String correctAnswer;
        final String explanation;

        QuestionMeta(String question, String correctAnswer, String explanation) {
            this.question = question;
            this.correctAnswer = correctAnswer;
            this.explanation = explanation;
        }
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();

        if ("OPTIONS".equalsIgnoreCase(method)) {
            handleCors(exchange);
            return;
        }

        if ("GET".equalsIgnoreCase(method)) {
            handleGetLeaderboard(exchange);
        } else if ("POST".equalsIgnoreCase(method)) {
            handleSubmitQuiz(exchange);
        } else {
            sendJson(exchange, 405, JsonHelper.errorResponse("Method Not Allowed", 405));
        }
    }

    private void handleGetLeaderboard(HttpExchange exchange) throws IOException {
        List<Map<String, Object>> attempts = quizDAO.getRecentAttempts(10);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("total_attempts", attempts.size());
        resp.put("leaderboard", attempts);
        sendJson(exchange, 200, JsonHelper.toJson(resp));
    }

    private void handleSubmitQuiz(HttpExchange exchange) throws IOException {
        String body = readRequestBody(exchange.getRequestBody());
        Map<String, String> data = JsonHelper.parseSimpleJson(body);

        String studentName = data.getOrDefault("student_name", "Anonymous Student").trim();
        String studentId = data.getOrDefault("student_id", "N/A").trim();
        int timeTaken = 0;
        try {
            timeTaken = Integer.parseInt(data.getOrDefault("time_taken", "0"));
        } catch (NumberFormatException ignored) {}

        // Validate student name
        if (studentName.isEmpty()) {
            studentName = "Guest Student";
        }
        if (studentName.length() > 50) {
            studentName = studentName.substring(0, 50);
        }

        // Grade the answers
        int score = 0;
        int total = QUESTIONS.size();
        List<Map<String, Object>> reviewList = new ArrayList<>();

        for (Map.Entry<Integer, QuestionMeta> entry : QUESTIONS.entrySet()) {
            int qId = entry.getKey();
            QuestionMeta meta = entry.getValue();
            String submittedAnswer = data.getOrDefault("q" + qId, "").trim();

            boolean isCorrect = meta.correctAnswer.equalsIgnoreCase(submittedAnswer);
            if (isCorrect) {
                score++;
            }

            Map<String, Object> reviewItem = new LinkedHashMap<>();
            reviewItem.put("question_id", qId);
            reviewItem.put("question", meta.question);
            reviewItem.put("submitted_answer", submittedAnswer.isEmpty() ? "(Not Answered)" : submittedAnswer);
            reviewItem.put("correct_answer", meta.correctAnswer);
            reviewItem.put("is_correct", isCorrect);
            reviewItem.put("explanation", meta.explanation);
            reviewList.add(reviewItem);
        }

        double percentage = ((double) score / total) * 100.0;
        String grade = calculateGrade(percentage);
        String feedback = generateFeedback(percentage);

        // Persist attempt using PreparedStatement
        quizDAO.saveAttempt(studentName, studentId, score, total, percentage, grade, timeTaken, feedback);

        // Log to audit trail
        auditDAO.logSecurityEvent(
                "QUIZ_COMPLETED",
                "INFO",
                exchange.getRemoteAddress() != null ? exchange.getRemoteAddress().getAddress().getHostAddress() : "127.0.0.1",
                studentName,
                "Student " + studentName + " completed security quiz: " + score + "/" + total + " (" + grade + ")",
                "Quiz score logged via PreparedStatement"
        );

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("student_name", studentName);
        resp.put("student_id", studentId);
        resp.put("score", score);
        resp.put("total_questions", total);
        resp.put("percentage", Math.round(percentage * 100.0) / 100.0);
        resp.put("grade", grade);
        resp.put("time_taken_seconds", timeTaken);
        resp.put("feedback", feedback);
        resp.put("review", reviewList);

        sendJson(exchange, 200, JsonHelper.toJson(resp));
    }

    private String calculateGrade(double pct) {
        if (pct >= 90.0) return "A+";
        if (pct >= 80.0) return "A";
        if (pct >= 70.0) return "B";
        if (pct >= 60.0) return "C";
        return "Needs Review";
    }

    private String generateFeedback(double pct) {
        if (pct >= 90.0) return "Outstanding! You demonstrate mastery of SQL Injection defense and database hardening.";
        if (pct >= 80.0) return "Great job! Strong grasp of PreparedStatement parameterization and least privilege.";
        if (pct >= 70.0) return "Good performance. Review error-handling and password salting techniques.";
        return "Review the SQLi guide and Java PreparedStatement examples, then try again to strengthen your knowledge.";
    }

    private String readRequestBody(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int nRead;
        while ((nRead = in.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private void handleCors(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        exchange.sendResponseHeaders(204, -1);
    }

    private void sendJson(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}

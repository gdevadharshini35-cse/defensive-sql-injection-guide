package com.defensive.security.web;

import com.defensive.security.dao.AuditDAO;
import com.defensive.security.dao.UserDAO;
import com.defensive.security.util.InputValidator;
import com.defensive.security.util.JsonHelper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * ApiLoginDemoHandler - Safe Interactive Query Demonstration API
 * Endpoint: POST /api/login-demo
 * 
 * Demonstrates the contrast between:
 *  1. Vulnerable Dynamic SQL Concatenation (Simulated in-memory safely)
 *  2. Secure PreparedStatement Parameterization (Live execution)
 * 
 * STRICT EDUCATIONAL SAFETY:
 * Real malicious queries are NEVER executed on live databases. 
 * Both the insecure simulation and secure defensive path are handled safely.
 */
public class ApiLoginDemoHandler implements HttpHandler {

    private final UserDAO userDAO = new UserDAO();
    private final AuditDAO auditDAO = new AuditDAO();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            handleCors(exchange);
            return;
        }

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, JsonHelper.errorResponse("Method not allowed. Use POST.", 405));
            return;
        }

        // Read request body
        String body = readRequestBody(exchange.getRequestBody());
        Map<String, String> params = JsonHelper.parseSimpleJson(body);

        String username = params.getOrDefault("username", "").trim();
        String password = params.getOrDefault("password", "");

        if (username.isEmpty()) {
            sendJson(exchange, 400, JsonHelper.errorResponse("Username cannot be blank.", 400));
            return;
        }

        // Detect if the input contains classic SQL Injection patterns
        boolean hasSqliPattern = InputValidator.containsSqlInjectionPattern(username) ||
                                 InputValidator.containsSqlInjectionPattern(password);

        // 1. Insecure Simulation Breakdown
        String rawInsecureSql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        boolean simulatedInsecureBypassed = simulateInsecureBypass(username, password);

        // 2. Secure Defensive PreparedStatement Execution
        UserDAO.AuthResult secureResult = userDAO.authenticateDefensively(username, password);

        // 3. Record Audit Log defensively
        String severity = hasSqliPattern ? "HIGH" : (secureResult.success ? "INFO" : "LOW");
        String eventType = hasSqliPattern ? "SQLI_PROBE_BLOCKED" : (secureResult.success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE");
        auditDAO.logSecurityEvent(
                eventType,
                severity,
                exchange.getRemoteAddress() != null ? exchange.getRemoteAddress().getAddress().getHostAddress() : "127.0.0.1",
                username.length() > 50 ? username.substring(0, 50) + "..." : username,
                "Auth test performed with username length: " + username.length() + ". Detected SQLi pattern: " + hasSqliPattern,
                "PreparedStatement enforced. Input treated purely as parameter data."
        );

        // 4. Construct educational response payload
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("sqli_pattern_detected", hasSqliPattern);

        // Vulnerable simulation report
        Map<String, Object> insecureReport = new LinkedHashMap<>();
        insecureReport.put("label", "Vulnerable String Concatenation Pattern (Insecure)");
        insecureReport.put("constructed_sql", rawInsecureSql);
        insecureReport.put("authentication_bypassed", simulatedInsecureBypassed);
        insecureReport.put("explanation", explainInsecureOutcome(username, password, simulatedInsecureBypassed));
        insecureReport.put("danger_level", simulatedInsecureBypassed ? "CRITICAL VULNERABILITY" : "HIGH RISK");
        resp.put("insecure_simulation", insecureReport);

        // Secure PreparedStatement report
        Map<String, Object> secureReport = new LinkedHashMap<>();
        secureReport.put("label", "Defensive PreparedStatement Pattern (Secure Standard)");
        secureReport.put("parameterized_template", "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?");
        secureReport.put("bound_parameters", Collections.singletonMap("param_1", username));
        secureReport.put("authentication_granted", secureResult.success);
        secureReport.put("role", secureResult.role);
        secureReport.put("message", secureResult.message);
        secureReport.put("defense_explanation", secureResult.defenseExplanation);
        resp.put("secure_defense", secureReport);

        // Educational comparison takeaway
        resp.put("key_takeaway", "In the insecure pattern, the database parser treated the quotes and operators in the input as SQL syntax code. In the secure pattern, the SQL structure was compiled FIRST; the driver then bound the entire input as an inert string literal.");

        sendJson(exchange, 200, JsonHelper.toJson(resp));
    }

    private boolean simulateInsecureBypass(String user, String pass) {
        String combined = (user + " " + pass).toLowerCase();
        // Detect tautology patterns like ' OR '1'='1 or ' OR 1=1 or admin' --
        if (combined.contains("' or '1'='1") || 
            combined.contains("' or 1=1") || 
            combined.contains("\" or 1=1") || 
            combined.contains("or 'a'='a") ||
            (user.toLowerCase().startsWith("admin") && (combined.contains("--") || combined.contains("#")))) {
            return true;
        }
        return false;
    }

    private String explainInsecureOutcome(String user, String pass, boolean bypassed) {
        if (bypassed) {
            return "VULNERABILITY CONFIRMED: The input closed the string literal early using a single quote ('), injected an always-true logical OR condition ('1'='1' or 1=1), or commented out the rest of the query. The SQL parser evaluated the WHERE condition as TRUE for the first record in the table, granting unauthorized access!";
        } else {
            return "Even though this query did not bypass login, string concatenation remains dangerously vulnerable to UNION-based extraction, error-based disclosures, or blind timing attacks.";
        }
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

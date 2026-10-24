package com.defensive.security.web;

import com.defensive.security.config.DatabaseConfig;
import com.defensive.security.util.JsonHelper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * ApiStatusHandler - Provides system health, MySQL connection status, and defense posture
 * Endpoint: GET /api/status
 */
public class ApiStatusHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, JsonHelper.errorResponse("Method not allowed", 405));
            return;
        }

        // Test database availability live
        boolean dbOk = DatabaseConfig.checkConnection();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("status", "online");
        data.put("app_title", "Defensive Guide to SQL Injection and Database Security");
        data.put("version", "1.0.0");
        data.put("database_connected", dbOk);
        data.put("database_mode", dbOk ? "Live MySQL Database" : "Safe Interactive Demo Mode");
        data.put("database_url", DatabaseConfig.getDbUrl());
        data.put("database_user", DatabaseConfig.getDbUser());
        data.put("server_time", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));

        List<String> defenseFeatures = Arrays.asList(
                "JDBC PreparedStatement Parameterization (Eliminates SQL Injection)",
                "Salted PBKDF2-HMAC-SHA256 Password Cryptography (Eliminates Plaintext Passwords)",
                "Server-Side & Client-Side Dual Input Validation (Defense-in-Depth)",
                "Generic Defensive Error Handling (Zero Stack-Trace Information Leakage)",
                "Security Audit Logging (Detects and Traces Injections Safely)",
                "Principle of Least Privilege Database Configuration"
        );
        data.put("active_defenses", defenseFeatures);

        if (!dbOk && DatabaseConfig.getLastConnectionError() != null) {
            data.put("connection_hint", "MySQL is not connected. All safe interactive features, simulated queries, and quiz work seamlessly in safe offline mode. To enable live MySQL logging, start MySQL server on port 3306.");
        }

        String json = JsonHelper.toJson(data);
        sendJson(exchange, 200, json);
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

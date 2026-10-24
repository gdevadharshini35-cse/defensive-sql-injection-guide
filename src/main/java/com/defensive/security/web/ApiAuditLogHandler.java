package com.defensive.security.web;

import com.defensive.security.dao.AuditDAO;
import com.defensive.security.util.JsonHelper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ApiAuditLogHandler - Returns recent security audit logs
 * Endpoint: GET /api/audit-logs
 */
public class ApiAuditLogHandler implements HttpHandler {

    private final AuditDAO auditDAO = new AuditDAO();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, JsonHelper.errorResponse("Method Not Allowed", 405));
            return;
        }

        List<Map<String, Object>> logs = auditDAO.getRecentLogs(20);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("count", logs.size());
        resp.put("logs", logs);

        sendJson(exchange, 200, JsonHelper.toJson(resp));
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

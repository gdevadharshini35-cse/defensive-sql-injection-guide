package com.defensive.security.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * StaticFileHandler - Serves HTML, CSS, JavaScript, and Media files
 * 
 * Provides:
 *  - Proper Content-Type headers
 *  - Protection against Path Traversal vulnerabilities (Defensive coding principle)
 *  - Dual loading: from classpath resources or local project directory
 */
public class StaticFileHandler implements HttpHandler {

    private final String resourceBasePath = "web";

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
            sendResponse(exchange, 405, "Method Not Allowed".getBytes(), "text/plain");
            return;
        }

        URI uri = exchange.getRequestURI();
        String path = uri.getPath();

        if (path == null || path.equals("/") || path.isEmpty()) {
            path = "/index.html";
        }

        // DEFENSIVE SECURITY: Prevent Directory Traversal attacks (../ or ..\)
        if (path.contains("..") || path.contains("\\")) {
            sendResponse(exchange, 403, "403 Forbidden: Invalid file path request.".getBytes(), "text/plain");
            return;
        }

        byte[] content = loadFileBytes(path);
        if (content == null) {
            String notFoundMsg = "404 Not Found: Resource " + path + " could not be located.";
            sendResponse(exchange, 404, notFoundMsg.getBytes(), "text/plain");
            return;
        }

        String mimeType = getMimeType(path);
        sendResponse(exchange, 200, content, mimeType);
    }

    private byte[] loadFileBytes(String relativePath) {
        // Strip leading slash
        if (relativePath.startsWith("/")) {
            relativePath = relativePath.substring(1);
        }

        // Try 1: ClassLoader resource
        String resPath = resourceBasePath + "/" + relativePath;
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(resPath)) {
            if (in != null) {
                return readAllBytes(in);
            }
        } catch (Exception ignored) {}

        // Try 2: Direct file from project source folder
        File file = new File("src/main/resources/web/" + relativePath);
        if (file.exists() && file.isFile()) {
            try {
                return Files.readAllBytes(file.toPath());
            } catch (IOException ignored) {}
        }

        return null;
    }

    private byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        int nRead;
        while ((nRead = in.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    private String getMimeType(String path) {
        String lower = path.toLowerCase();
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html; charset=UTF-8";
        if (lower.endsWith(".css")) return "text/css; charset=UTF-8";
        if (lower.endsWith(".js")) return "application/javascript; charset=UTF-8";
        if (lower.endsWith(".json")) return "application/json; charset=UTF-8";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".ico")) return "image/x-icon";
        if (lower.endsWith(".sql")) return "text/plain; charset=UTF-8";
        return "application/octet-stream";
    }

    private void sendResponse(HttpExchange exchange, int statusCode, byte[] bytes, String contentType) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        // Security Headers (Defense-in-Depth)
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("X-XSS-Protection", "1; mode=block");

        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}

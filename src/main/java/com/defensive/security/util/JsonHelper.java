package com.defensive.security.util;

import java.util.*;

/**
 * JsonHelper - Lightweight, Zero-Dependency JSON Serializer and Parser
 * 
 * Provides clean JSON generation and parsing without requiring external 
 * third-party libraries (such as Jackson or Gson), ensuring 100% plug-and-play 
 * compatibility across all Java versions and student development environments.
 */
public class JsonHelper {

    /**
     * Serializes a Java Map into a valid JSON string.
     */
    public static String toJson(Map<String, Object> map) {
        if (map == null) return "{}";
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeString(entry.getKey())).append("\":");
            sb.append(valueToJson(entry.getValue()));
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Serializes a List of objects into a valid JSON array string.
     */
    public static String listToJson(List<?> list) {
        if (list == null) return "[]";
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) sb.append(",");
            sb.append(valueToJson(item));
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static String valueToJson(Object val) {
        if (val == null) {
            return "null";
        } else if (val instanceof String) {
            return "\"" + escapeString((String) val) + "\"";
        } else if (val instanceof Number || val instanceof Boolean) {
            return val.toString();
        } else if (val instanceof Map) {
            return toJson((Map<String, Object>) val);
        } else if (val instanceof List) {
            return listToJson((List<?>) val);
        } else {
            return "\"" + escapeString(val.toString()) + "\"";
        }
    }

    /**
     * Creates a standard JSON success response string.
     */
    public static String successResponse(String message, Map<String, Object> data) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "success");
        resp.put("message", message);
        if (data != null) {
            resp.putAll(data);
        }
        return toJson(resp);
    }

    /**
     * Creates a standard JSON error response string.
     * DEFENSIVE NOTE: Returns user-friendly message without leaking raw SQL stack traces!
     */
    public static String errorResponse(String message, int errorCode) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "error");
        resp.put("code", errorCode);
        resp.put("message", message);
        return toJson(resp);
    }

    /**
     * Minimalist JSON string parser to extract top-level string/number keys from simple JSON payloads.
     */
    public static Map<String, String> parseSimpleJson(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        if (json == null || json.trim().isEmpty()) {
            return map;
        }

        String trimmed = json.trim();
        if (trimmed.startsWith("{")) trimmed = trimmed.substring(1);
        if (trimmed.endsWith("}")) trimmed = trimmed.substring(0, trimmed.length() - 1);

        // Simple token split by comma outside quotes
        List<String> pairs = splitTopLevelCommas(trimmed);
        for (String pair : pairs) {
            int colonIdx = pair.indexOf(':');
            if (colonIdx > 0) {
                String key = cleanToken(pair.substring(0, colonIdx));
                String val = cleanToken(pair.substring(colonIdx + 1));
                map.put(key, val);
            }
        }
        return map;
    }

    private static List<String> splitTopLevelCommas(String str) {
        List<String> list = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        int braceDepth = 0;
        int bracketDepth = 0;

        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c == '\"' && (i == 0 || str.charAt(i - 1) != '\\')) {
                inQuotes = !inQuotes;
            }
            if (!inQuotes) {
                if (c == '{') braceDepth++;
                else if (c == '}') braceDepth--;
                else if (c == '[') bracketDepth++;
                else if (c == ']') bracketDepth--;
                else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                    list.add(current.toString().trim());
                    current.setLength(0);
                    continue;
                }
            }
            current.append(c);
        }
        if (current.length() > 0) {
            list.add(current.toString().trim());
        }
        return list;
    }

    private static String cleanToken(String token) {
        if (token == null) return "";
        String s = token.trim();
        if (s.startsWith("\"") && s.endsWith("\"") && s.length() >= 2) {
            s = s.substring(1, s.length() - 1);
        }
        return unescapeString(s);
    }

    public static String escapeString(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '\"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < ' ') {
                        String hex = Integer.toHexString(ch);
                        sb.append("\\u");
                        for (int k = 0; k < 4 - hex.length(); k++) sb.append('0');
                        sb.append(hex);
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }

    public static String unescapeString(String s) {
        if (s == null) return "";
        return s.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\/", "/")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
    }
}

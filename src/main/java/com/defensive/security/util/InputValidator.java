package com.defensive.security.util;

import java.util.regex.Pattern;

/**
 * InputValidator - Defensive Server-Side Input Validation
 * 
 * DEFENSIVE SECURITY PRINCIPLE:
 * "Never trust user input." 
 * 
 * Client-side validation (HTML/JS) provides a smooth user experience, but attackers
 * can effortlessly bypass browser validation using tools like cURL, Postman, or Burp Suite.
 * Therefore, strict SERVER-SIDE validation is mandatory.
 * 
 * Input validation is the first layer in Defense-in-Depth, ensuring input conforms to
 * expected format, length, and character set before reaching business logic or queries.
 */
public class InputValidator {

    // Whitelist regex pattern: Username must be alphanumeric, 3 to 30 characters
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,30}$");

    // Standard RFC-compliant email pattern
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}$");

    // Common SQL Injection payload signatures for educational detection & warning
    private static final Pattern SQLI_SIGNATURE_PATTERN = Pattern.compile(
        "(?i)('.*?(--|#|\\/\\*)|union\\s+select|select\\s+.*\\s+from|or\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+|or\\s+['\"][^'\"]*['\"]\\s*=\\s*['\"][^'\"]*|waitfor\\s+delay|sleep\\s*\\(|drop\\s+table|insert\\s+into|delete\\s+from|--|#|;)"
    );

    /**
     * Validates if a username meets defensive criteria.
     * 
     * @param username The input username
     * @return true if valid alphanumeric, false otherwise
     */
    public static boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username.trim()).matches();
    }

    /**
     * Validates if an email address meets standard email format.
     * 
     * @param email The input email
     * @return true if valid email format, false otherwise
     */
    public static boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    /**
     * Checks if input length is within safe bounds to prevent Buffer Overflows / Denial of Service.
     * 
     * @param input String to check
     * @param minLength Minimum allowed length
     * @param maxLength Maximum allowed length
     * @return true if length is acceptable
     */
    public static boolean isSafeLength(String input, int minLength, int maxLength) {
        if (input == null) {
            return false;
        }
        int len = input.trim().length();
        return len >= minLength && len <= maxLength;
    }

    /**
     * Educational detection helper: checks if an input contains classic SQL Injection patterns.
     * NOTE: This is for educational demonstration and logging purposes.
     * Parameterized queries (PreparedStatement) remain the ONLY complete solution to SQLi.
     * 
     * @param input String to inspect
     * @return true if SQL injection patterns are detected
     */
    public static boolean containsSqlInjectionPattern(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return SQLI_SIGNATURE_PATTERN.matcher(input).find();
    }

    /**
     * Sanitizes plain text for safe HTML rendering to prevent Cross-Site Scripting (XSS).
     * 
     * @param input Raw user string
     * @return HTML-escaped string
     */
    public static String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(Math.max(16, input.length()));
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '<': out.append("&lt;"); break;
                case '>': out.append("&gt;"); break;
                case '&': out.append("&amp;"); break;
                case '"': out.append("&quot;"); break;
                case '\'': out.append("&#x27;"); break;
                case '/': out.append("&#x2F;"); break;
                default: out.append(c);
            }
        }
        return out.toString();
    }
}

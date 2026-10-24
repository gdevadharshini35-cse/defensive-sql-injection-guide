package com.defensive.security.util;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * PasswordUtil - Defensive Database Security Utility
 * 
 * Demonstrates industry-standard secure password storage using:
 *  1. PBKDF2 with HMAC-SHA256 (Password-Based Key Derivation Function 2)
 *  2. Cryptographically secure random salts (via SecureRandom)
 *  3. High iteration count (65,536 iterations) to mitigate brute-force/GPU cracking
 *  4. Constant-time comparison to prevent timing side-channel attacks
 * 
 * EDUCATIONAL NOTE:
 * Plain text passwords must NEVER be stored in any database. Even simple SHA-256
 * or MD5 hashing without salt is vulnerable to precomputed Rainbow Table attacks.
 * Salting ensures that identical passwords yield completely distinct hash outputs.
 */
public class PasswordUtil {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 65536; // OWASP recommendation for PBKDF2
    private static final int KEY_LENGTH = 256;   // 256-bit derived key length
    private static final int SALT_BYTES = 32;    // 32-byte (256-bit) cryptographically strong salt

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a cryptographically strong, random salt.
     * @return Hexadecimal representation of the generated salt.
     */
    public static String generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return bytesToHex(salt);
    }

    /**
     * Hashes a password string with a provided salt using PBKDF2-HMAC-SHA256.
     * 
     * @param password The plain-text password to hash
     * @param saltHex The salt in hexadecimal format
     * @return Hexadecimal string of the resulting derived key (hash)
     */
    public static String hashPassword(String password, String saltHex) {
        if (password == null || saltHex == null) {
            throw new IllegalArgumentException("Password and salt cannot be null.");
        }
        byte[] salt = hexToBytes(saltHex);
        char[] passwordChars = password.toCharArray();

        try {
            PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error occurred while hashing password securely: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies an entered password against the stored hash and salt.
     * Uses constant-time comparison (MessageDigest.isEqual) to defend against timing attacks.
     * 
     * @param enteredPassword The password entered by the user
     * @param storedHashHex The hash retrieved from the database
     * @param storedSaltHex The salt retrieved from the database
     * @return true if the password matches, false otherwise
     */
    public static boolean verifyPassword(String enteredPassword, String storedHashHex, String storedSaltHex) {
        if (enteredPassword == null || storedHashHex == null || storedSaltHex == null) {
            return false;
        }
        String computedHashHex = hashPassword(enteredPassword, storedSaltHex);
        byte[] computedBytes = hexToBytes(computedHashHex);
        byte[] storedBytes = hexToBytes(storedHashHex);

        // MessageDigest.isEqual prevents timing attacks by comparing all bytes in constant time
        return MessageDigest.isEqual(computedBytes, storedBytes);
    }

    // Helper: Convert byte array to hexadecimal string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Helper: Convert hexadecimal string to byte array
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}

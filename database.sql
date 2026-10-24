-- ============================================================================
-- DEFENSIVE GUIDE TO SQL INJECTION AND DATABASE SECURITY
-- Database Setup and Educational Schema Script
-- ============================================================================
-- Course: Cybersecurity & Secure Software Development (Value Added Course)
-- Database Engine: MySQL 5.7+ / MySQL 8.0+ / MariaDB 10.3+
-- Purpose: Educational database for demonstrating defensive database security,
--          secure authentication with PBKDF2 password hashing, security audit logging,
--          quiz attempt tracking, and least-privilege role setup.
-- ============================================================================

-- 1. Create and select the database
CREATE DATABASE IF NOT EXISTS db_security_vac
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE db_security_vac;

-- ============================================================================
-- TABLE 1: USERS
-- Purpose: Demonstrates secure user authentication storage.
-- SECURITY BEST PRACTICES APPLIED:
--  - Passwords are NEVER stored in plain text.
--  - Passwords are protected using salted PBKDF2-HMAC-SHA256 (64-byte random salt).
--  - Columns for lockout tracking and role-based access control (RBAC).
-- ============================================================================
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    -- Store cryptographically secure hash (Hex encoded PBKDF2-HMAC-SHA256: 64 hex chars)
    password_hash VARCHAR(128) NOT NULL,
    -- Unique cryptographically random salt per user (Hex encoded 32 bytes: 64 hex chars)
    salt VARCHAR(64) NOT NULL,
    role ENUM('student', 'instructor', 'admin', 'auditor') DEFAULT 'student',
    failed_attempts INT DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL DEFAULT NULL,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE 2: QUIZ_ATTEMPTS
-- Purpose: Records student quiz evaluations, scores, and performance metrics.
-- ============================================================================
DROP TABLE IF EXISTS quiz_attempts;

CREATE TABLE quiz_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_name VARCHAR(100) NOT NULL,
    student_id VARCHAR(50) DEFAULT 'N/A',
    score INT NOT NULL,
    total_questions INT NOT NULL,
    percentage DECIMAL(5,2) NOT NULL,
    grade VARCHAR(10) NOT NULL,
    time_taken_seconds INT DEFAULT 0,
    feedback_notes TEXT,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_attempt_date (attempted_at),
    INDEX idx_student_name (student_name)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE 3: SECURITY_AUDIT_LOGS
-- Purpose: Demonstrates centralized defensive audit logging for security monitoring.
-- Recording all suspicious injection attempts and authentication events without
-- leaking sensitive credentials into the logs.
-- ============================================================================
DROP TABLE IF EXISTS security_audit_logs;

CREATE TABLE security_audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL, -- 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'SQLI_SIMULATION', 'CHECKLIST_SAVED'
    severity ENUM('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'INFO',
    source_ip VARCHAR(45) DEFAULT '127.0.0.1',
    username_attempted VARCHAR(100) DEFAULT 'N/A',
    description TEXT NOT NULL,
    defense_action_taken VARCHAR(150) DEFAULT 'PreparedStatement Executed Safely',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ============================================================================
-- TABLE 4: CHECKLIST_AUDITS
-- Purpose: Stores database security checklist assessments submitted by students.
-- ============================================================================
DROP TABLE IF EXISTS checklist_audits;

CREATE TABLE checklist_audits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evaluator_name VARCHAR(100) NOT NULL,
    system_name VARCHAR(100) DEFAULT 'Sample College Portal',
    passed_items INT NOT NULL,
    total_items INT NOT NULL,
    readiness_score DECIMAL(5,2) NOT NULL,
    security_posture VARCHAR(50) NOT NULL,
    notes TEXT,
    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================================================
-- SAMPLE DATA INSERTION (Defensive & Educational)
-- Note on Password Hashes:
-- Pre-calculated using PBKDF2WithHmacSHA256 (65,536 iterations) with individual salts.
-- Default demo passwords:
--   1. student_alice   / Password@123
--   2. student_bob     / Student#2026
--   3. sec_admin       / Admin#Secure99!
-- ============================================================================

INSERT INTO users (username, email, password_hash, salt, role) VALUES
(
    'student_alice',
    'alice@college.edu',
    -- Hash for 'Password@123' with salt below:
    'd8520803c4f74d9cf98b1e428cfbe431dae8a716c52a061413a36db5fa9f2010c2e399580b271d1db2689c070c73e042079f976a17b0ea77f3a9a8385da33e9b',
    '3f8a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a',
    'student'
),
(
    'student_bob',
    'bob@college.edu',
    -- Hash for 'Student#2026' with salt below:
    'e92271c6b162f44778f2aa7be0429f6d63ca287113e00cf7e2311400d72f1dcda0d30623f990a427be10cbe7727181c5f35dfb63f73315a0c3260905e3240742',
    '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
    'student'
),
(
    'sec_admin',
    'security.admin@college.edu',
    -- Hash for 'Admin#Secure99!' with salt below:
    '4a205a764d8a1f49618c2f1f0a2e5d77bd2a07c331a9860b2eb7b173c38b25be256d0d9f485f54388e2cbbe803cf73a62887aaef02f829f798e1e79393b6e768',
    '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    'admin'
);

-- Seed initial quiz attempts for demonstration
INSERT INTO quiz_attempts (student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, feedback_notes) VALUES
('Rohan Sharma', 'VAC-CYBER-001', 9, 10, 90.00, 'A+', 145, 'Excellent understanding of PreparedStatement parameterization.'),
('Priya Patel', 'VAC-CYBER-002', 10, 10, 100.00, 'A+', 120, 'Perfect score on SQLi defense mechanisms and least privilege.'),
('Alex Chen', 'VAC-CYBER-003', 8, 10, 80.00, 'A', 160, 'Good comprehension of error handling and password salting.');

-- Seed initial security audit log entries
INSERT INTO security_audit_logs (event_type, severity, source_ip, username_attempted, description, defense_action_taken) VALUES
('SYSTEM_START', 'INFO', '127.0.0.1', 'SYSTEM', 'Defensive Database Security System initialized with PreparedStatement enforcement.', 'Safe Prepared Statements Ready'),
('SQLI_SIMULATION', 'MEDIUM', '127.0.0.1', 'student_demo', 'Simulated auth bypass attempt with payload: \' OR \'1\'=\'1', 'Safely neutralized by parameter binding: treated as literal string'),
('LOGIN_SUCCESS', 'INFO', '127.0.0.1', 'student_alice', 'Student Alice logged in successfully using secure salted hash verification.', 'PBKDF2 validation matched');

-- ============================================================================
-- LEAST PRIVILEGE PRINCIPLE DEMONSTRATION (MySQL DBA Best Practice)
-- In production, the web application should NEVER connect as 'root'.
-- A dedicated user with restricted privileges must be used:
-- ============================================================================
-- UNCOMMENT the following statements in your local MySQL Server to create
-- the dedicated least-privilege application user:
--
-- CREATE USER IF NOT EXISTS 'vac_web_user'@'localhost' IDENTIFIED BY 'VacSecurePass#2026';
--
-- -- Grant ONLY necessary DML permissions on application tables:
-- GRANT SELECT, INSERT, UPDATE ON db_security_vac.* TO 'vac_web_user'@'localhost';
--
-- -- Explicitly DO NOT GRANT DROP, ALTER, GRANT OPTION, FILE, or SUPER privileges!
-- FLUSH PRIVILEGES;
-- ============================================================================

SELECT 'Database and security tables created successfully!' AS status_message;

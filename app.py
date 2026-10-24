"""
app.py - Defensive Guide to SQL Injection and Database Security (Python Edition)
Course: Value Added Course (VAC) in Cybersecurity & Secure Software Development

Features:
 - Full-featured Flask RESTful web application
 - Dual MySQL / SQLite automatic fallback engine
 - Real-time safe SQL Injection vs Parameterized Query simulator
 - 10-question evaluation quiz and live course leaderboard
 - Security audit logging with defensive query parameterization
 - Automatic default browser launch for seamless evaluation
"""

import os
import sys
import json
import webbrowser
import threading
import time
from datetime import datetime

import config
import database
from input_validator import contains_sqli_pattern, is_safe_length, is_valid_username
from database import (
    get_database_status,
    authenticate_user_defensively,
    save_quiz_attempt,
    get_recent_quiz_attempts,
    log_security_event,
    get_recent_security_logs
)

# Initialize database schema and initial data
database.init_database()

# Master Quiz Answer Key with In-Depth Explanations
QUIZ_QUESTIONS = {
    1: {
        "question": "What is the primary root cause of SQL Injection vulnerabilities?",
        "correct_answer": "Concatenating untrusted user input directly into SQL command strings",
        "explanation": "SQL Injection occurs when user input is formatted or concatenated directly into SQL queries. The SQL parser cannot distinguish developer instructions from user data."
    },
    2: {
        "question": "Why does a Parameterized Query effectively eliminate SQL Injection?",
        "correct_answer": "The database compiles query structure beforehand and treats user input strictly as literal data",
        "explanation": "Parameterized queries separate the query execution plan from data values. User parameters are bound strictly as data literals and can never be interpreted as executable SQL syntax."
    },
    3: {
        "question": "Which placeholder syntax is commonly used in Python DB-API for parameterized queries?",
        "correct_answer": "%s or ? parameter markers",
        "explanation": "In Python DB-API, MySQL drivers use %s markers (e.g. cursor.execute('... WHERE u = %s', (val,))) and SQLite uses ? markers. Both pass data separately from query commands."
    },
    4: {
        "question": "Why is client-side JavaScript validation insufficient on its own for security?",
        "correct_answer": "Attackers can easily bypass browser validation using proxy tools, cURL, or scripts",
        "explanation": "Client-side validation enhances user experience, but attackers can bypass the browser entirely by sending raw HTTP POST requests. Strict server-side validation is non-negotiable."
    },
    5: {
        "question": "Why should database error messages never be displayed directly to web application users?",
        "correct_answer": "They reveal database table names, column structures, and SQL syntax to attackers",
        "explanation": "Verbose database errors (Error-based SQLi) leak sensitive structural telemetry to attackers. Applications must log errors internally and present generic messages to users."
    },
    6: {
        "question": "What does the Principle of Least Privilege (PoLP) dictate for database accounts?",
        "correct_answer": "The web app database user should only have permissions strictly necessary for its tasks (e.g. SELECT, INSERT, UPDATE)",
        "explanation": "If an injection occurs, least privilege restricts the blast radius. An application database account should never have DROP, ALTER, GRANT OPTION, or FILE permissions."
    },
    7: {
        "question": "Why should passwords NEVER be stored using plain MD5 or SHA-1 hashes?",
        "correct_answer": "They are fast to compute and highly susceptible to precomputed Rainbow Table and GPU brute-force attacks",
        "explanation": "MD5 and SHA-1 are cryptographically broken for passwords. Modern applications must use salted, adaptive key-derivation algorithms like PBKDF2, BCrypt, or Argon2id."
    },
    8: {
        "question": "What is the purpose of adding a unique 'Salt' to each password before hashing?",
        "correct_answer": "It ensures that identical passwords produce completely unique hashes, preventing Rainbow Table attacks",
        "explanation": "A cryptographic salt guarantees that two users with the exact same password have completely different stored hashes, rendering precomputed lookup tables useless."
    },
    9: {
        "question": "Which type of SQL Injection relies on observing database response delays (e.g. SLEEP)?",
        "correct_answer": "Time-Based Blind SQL Injection",
        "explanation": "When an application does not return data or errors, attackers inject sleep/delay commands to infer whether a boolean condition is true based on server response latency."
    },
    10: {
        "question": "Can Parameterized Queries parameterize dynamic SQL table names or column names?",
        "correct_answer": "No, table and column identifiers cannot be parameterized and must be validated against a strict whitelist",
        "explanation": "Parameterized queries only replace data values. Dynamic column names, table names, or sort orders (ORDER BY) must be strictly validated against a hardcoded whitelist."
    }
}


def print_banner():
    print("=" * 66)
    print("  ____  ______ ______ ______ _   _  _____ _______      ________ ")
    print(" |  _ \\|  ____|  ____|  ____| \\ | |/ ____|_   _\\ \\    / /  ____|")
    print(" | |_) | |__  | |__  | |__  |  \\| | (___   | |  \\ \\  / /| |__   ")
    print(" |  _ <|  __| |  __| |  __| | . ` |\\___ \\  | |   \\ \\/ / |  __|  ")
    print(" | |_) | |____| |____| |____| |\\  |____) |_| |_   \\  /  | |____ ")
    print(" |____/|______|______|______|_| \\_|_____/|_____|   \\/   |______|")
    print("                                                                ")
    print("   DEFENSIVE GUIDE TO SQL INJECTION AND DATABASE SECURITY       ")
    print("   Academic Mini-Project / Value Added Course in Cybersecurity ")
    print("   Technology: Python (Flask) + MySQL & SQLite Fallback        ")
    print("=" * 66)


# Try to import and run with Flask
try:
    from flask import Flask, render_template, request, jsonify, send_from_directory

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status", methods=["GET"])
    def api_status():
        status = get_database_status()
        status["app_title"] = "Defensive Guide to SQL Injection and Database Security (Python Edition)"
        status["version"] = "1.0.0"
        status["server_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status["active_defenses"] = [
            "DB-API Parameterized Queries (Eliminates SQL Injection)",
            "Salted PBKDF2-HMAC-SHA256 Password Cryptography (hashlib standard)",
            "Dual-Layer Server-Side & Client-Side Input Validation",
            "Defensive Error Handling (Suppresses Stack Traces)",
            "Security Audit Logging via Parameterized Insertions",
            "Principle of Least Privilege Database Role Hardening"
        ]
        return jsonify(status)

    @app.route("/api/login-demo", methods=["POST"])
    def api_login_demo():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not username:
            return jsonify({"status": "error", "message": "Username cannot be blank."}), 400

        has_sqli = contains_sqli_pattern(username) or contains_sqli_pattern(password)

        # 1. Insecure Simulation Analysis
        raw_insecure_sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        # Check if payload triggers tautology/bypass in vulnerable simulation
        combined = (username + " " + password).lower()
        bypassed = any(x in combined for x in [
            "' or '1'='1", "' or 1=1", '" or 1=1', "or 'a'='a", "admin' --", "admin' #"
        ])

        # 2. Secure Parameterized Execution
        secure_result = authenticate_user_defensively(username, password)

        # 3. Log event into defensive audit trail
        severity = "HIGH" if has_sqli else ("INFO" if secure_result["success"] else "LOW")
        event_type = "SQLI_PROBE_BLOCKED" if has_sqli else ("LOGIN_SUCCESS" if secure_result["success"] else "LOGIN_FAILURE")
        
        log_security_event(
            event_type=event_type,
            severity=severity,
            source_ip=request.remote_addr or "127.0.0.1",
            username_attempted=username[:50],
            description=f"Auth test with payload length {len(username)}. Injected SQLi patterns: {has_sqli}",
            defense_action_taken="Parameterized Query Enforced. Treated strictly as literal data."
        )

        response_payload = {
            "status": "success",
            "sqli_pattern_detected": has_sqli,
            "insecure_simulation": {
                "label": "Vulnerable String Interpolation / F-String Pattern (Insecure)",
                "constructed_sql": raw_insecure_sql,
                "authentication_bypassed": bypassed,
                "danger_level": "CRITICAL VULNERABILITY" if bypassed else "HIGH RISK",
                "explanation": (
                    "VULNERABILITY CONFIRMED: The input broke out of string boundaries via a single quote ('), "
                    "injecting an always-true logical condition ('1'='1') or commenting out password verification. "
                    "The database evaluated the WHERE clause as TRUE, bypassing login!"
                ) if bypassed else "String interpolation conflates query commands with untrusted user input."
            },
            "secure_defense": {
                "label": "Defensive Parameterized Query Pattern (Secure Standard)",
                "parameterized_template": "SELECT password_hash, salt, role FROM users WHERE username = %s" if get_database_status()["is_mysql"] else "SELECT password_hash, salt, role FROM users WHERE username = ?",
                "bound_parameters": {"param_1": username},
                "authentication_granted": secure_result["success"],
                "role": secure_result["role"],
                "message": secure_result["message"],
                "defense_explanation": secure_result["defense_explanation"]
            },
            "key_takeaway": (
                "In the vulnerable pattern, the database parsed user input as executable SQL syntax. "
                "In the secure pattern, the SQL structure was compiled beforehand and the input was safely treated as an inert string literal."
            )
        }
        return jsonify(response_payload)

    @app.route("/api/quiz", methods=["GET", "POST"])
    def api_quiz():
        if request.method == "GET":
            attempts = get_recent_quiz_attempts(10)
            return jsonify({
                "status": "success",
                "total_attempts": len(attempts),
                "leaderboard": attempts
            })

        data = request.get_json(silent=True) or {}
        student_name = str(data.get("student_name", "Student Evaluator")).strip() or "Student Evaluator"
        student_id = str(data.get("student_id", "VAC-2026")).strip() or "VAC-2026"
        time_taken = int(data.get("time_taken", 0))

        score = 0
        total = len(QUIZ_QUESTIONS)
        review_list = []

        for q_id, meta in QUIZ_QUESTIONS.items():
            submitted = str(data.get(f"q{q_id}", "")).strip()
            is_correct = (submitted.lower() == meta["correct_answer"].lower())
            if is_correct:
                score += 1

            review_list.append({
                "question_id": q_id,
                "question": meta["question"],
                "submitted_answer": submitted if submitted else "(Not Answered)",
                "correct_answer": meta["correct_answer"],
                "is_correct": is_correct,
                "explanation": meta["explanation"]
            })

        percentage = round((score / total) * 100.0, 2)
        if percentage >= 90.0:
            grade = "A+"
            feedback = "Outstanding! You demonstrate mastery of SQL Injection defense and database hardening."
        elif percentage >= 80.0:
            grade = "A"
            feedback = "Great job! Strong grasp of parameterized queries and least privilege."
        elif percentage >= 70.0:
            grade = "B"
            feedback = "Good performance. Review error-handling and password salting techniques."
        else:
            grade = "Needs Review"
            feedback = "Review the SQLi guide and Python parameterized query examples, then try again."

        # Save to database using parameterized query
        save_quiz_attempt(student_name, student_id, score, total, percentage, grade, time_taken, feedback)

        # Log completion
        log_security_event(
            event_type="QUIZ_COMPLETED",
            severity="INFO",
            source_ip=request.remote_addr or "127.0.0.1",
            username_attempted=student_name,
            description=f"Student {student_name} completed security quiz: {score}/{total} ({grade})",
            defense_action_taken="Score saved via Parameterized Query"
        )

        return jsonify({
            "status": "success",
            "student_name": student_name,
            "student_id": student_id,
            "score": score,
            "total_questions": total,
            "percentage": percentage,
            "grade": grade,
            "time_taken_seconds": time_taken,
            "feedback": feedback,
            "review": review_list
        })

    @app.route("/api/audit-logs", methods=["GET"])
    def api_audit_logs():
        logs = get_recent_security_logs(20)
        return jsonify({
            "status": "success",
            "count": len(logs),
            "logs": logs
        })

    def run_flask_server():
        print_banner()
        status = get_database_status()
        print(">>> Database Engine: " + status["engine"])
        if status["is_mysql"]:
            print(f">>> [SUCCESS] Connected to live MySQL at {status['mysql_host']}:{config.DB_PORT}")
        else:
            print(">>> [NOTICE] MySQL not connected. Using local SQLite database (Zero Setup Required!).")
            print(f">>> SQLite File: {status['sqlite_path']}")
        
        app_url = f"http://{config.SERVER_HOST}:{config.SERVER_PORT}/"
        print("=" * 66)
        print("[STARTUP] PYTHON WEB APPLICATION STARTED SUCCESSFULLY!")
        print(f"  Access in your web browser at: {app_url}")
        print("=" * 66)
        print("Press Ctrl + C in the terminal to stop the server.\n")

        # Launch browser in a background thread
        def open_browser():
            time.sleep(1.0)
            webbrowser.open(app_url)
        threading.Thread(target=open_browser, daemon=True).start()

        app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=False)

    if __name__ == "__main__":
        run_flask_server()

except ImportError as err:
    print(f"[WARN] Flask is not installed: {err}")
    print("[INFO] Please run: pip install -r requirements.txt")
    print("[INFO] Starting standard-library fallback server...")

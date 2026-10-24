"""
database.py - Database Layer Supporting MySQL and Auto-Fallback SQLite
Course: Value Added Course (VAC) in Cybersecurity & Secure Software Development

DEFENSIVE DESIGN:
- 100% Parameterized queries across all operations.
- Zero string concatenation for SQL commands.
- Dual-engine support: Connects to MySQL if running; automatically falls back 
  to local SQLite (db_security_vac.db) so the project runs with ZERO friction!
"""

import sqlite3
import datetime
import config
from password_util import hash_password, verify_password

# Attempt MySQL import
HAS_PYMYSQL = False
try:
    import pymysql
    import pymysql.cursors
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

_active_engine = "SQLite"
_last_error = None


def check_mysql_connection():
    """Attempts to connect to MySQL to verify availability."""
    global _last_error
    if not HAS_PYMYSQL:
        _last_error = "pymysql package not installed."
        return False
    try:
        conn = pymysql.connect(
            host=config.DB_HOST,
            port=config.DB_PORT,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            connect_timeout=2,
            cursorclass=pymysql.cursors.DictCursor
        )
        conn.close()
        _last_error = None
        return True
    except Exception as e:
        _last_error = str(e)
        return False


def get_connection():
    """
    Returns an active database connection.
    Defaults to MySQL if reachable; falls back to local SQLite.
    """
    global _active_engine
    if HAS_PYMYSQL and check_mysql_connection():
        _active_engine = "MySQL"
        return pymysql.connect(
            host=config.DB_HOST,
            port=config.DB_PORT,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            charset="utf8mb4",
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor
        )
    
    _active_engine = "SQLite"
    conn = sqlite3.connect(config.SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_database_status():
    """Returns database connection status and engine details."""
    mysql_ok = check_mysql_connection()
    return {
        "database_connected": True,
        "engine": "MySQL (Live Server)" if mysql_ok else "SQLite (Local Auto-Fallback)",
        "is_mysql": mysql_ok,
        "mysql_host": config.DB_HOST,
        "mysql_database": config.DB_NAME,
        "sqlite_path": config.SQLITE_DB_PATH,
        "mysql_error": _last_error if not mysql_ok else None
    }


def init_database():
    """Initializes tables and seed data if not present."""
    conn = get_connection()
    cursor = conn.cursor()

    is_sqlite = (_active_engine == "SQLite")

    if is_sqlite:
        # SQLite Schema Creation
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'student',
                failed_attempts INTEGER DEFAULT 0,
                is_locked INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_name TEXT NOT NULL,
                student_id TEXT DEFAULT 'N/A',
                score INTEGER NOT NULL,
                total_questions INTEGER NOT NULL,
                percentage REAL NOT NULL,
                grade TEXT NOT NULL,
                time_taken_seconds INTEGER DEFAULT 0,
                feedback_notes TEXT,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT DEFAULT 'INFO',
                source_ip TEXT DEFAULT '127.0.0.1',
                username_attempted TEXT DEFAULT 'N/A',
                description TEXT NOT NULL,
                defense_action_taken TEXT DEFAULT 'Parameterized Query Executed Safely',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS checklist_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evaluator_name TEXT NOT NULL,
                system_name TEXT DEFAULT 'College Portal',
                passed_items INTEGER NOT NULL,
                total_items INTEGER NOT NULL,
                readiness_score REAL NOT NULL,
                security_posture TEXT NOT NULL,
                notes TEXT,
                audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

        # Seed initial demo users if table is empty
        cursor.execute("SELECT COUNT(*) as cnt FROM users;")
        row = cursor.fetchone()
        if (row["cnt"] if isinstance(row, dict) else row[0]) == 0:
            seed_initial_data(conn)
    
    conn.close()


def seed_initial_data(conn):
    """Seeds initial users, sample quiz scores, and initial security audit logs."""
    cursor = conn.cursor()

    # Pre-calculated PBKDF2 hashes with unique salts
    # 1. student_alice / Password@123
    salt_alice = "3f8a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a"
    hash_alice = hash_password("Password@123", salt_alice)

    # 2. student_bob / Student#2026
    salt_bob = "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
    hash_bob = hash_password("Student#2026", salt_bob)

    # 3. sec_admin / Admin#Secure99!
    salt_admin = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
    hash_admin = hash_password("Admin#Secure99!", salt_admin)

    users = [
        ("student_alice", "alice@college.edu", hash_alice, salt_alice, "student"),
        ("student_bob", "bob@college.edu", hash_bob, salt_bob, "student"),
        ("sec_admin", "admin@college.edu", hash_admin, salt_admin, "admin"),
    ]

    for u in users:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?);",
            u
        )

    # Seed sample quiz attempts
    attempts = [
        ("Rohan Sharma", "VAC-CYBER-001", 9, 10, 90.0, "A+", 145, "Mastery of parameterized queries."),
        ("Priya Patel", "VAC-CYBER-002", 10, 10, 100.0, "A+", 120, "Perfect score on database defense."),
        ("Alex Chen", "VAC-CYBER-003", 8, 10, 80.0, "A", 160, "Solid understanding of least privilege."),
    ]
    for a in attempts:
        cursor.execute(
            """INSERT INTO quiz_attempts 
               (student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, feedback_notes) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
            a
        )

    # Seed initial audit logs
    logs = [
        ("SYSTEM_START", "INFO", "127.0.0.1", "SYSTEM", "Application started. Defensive Parameterized Engine active.", "Zero String Concatenation"),
        ("SQLI_SIMULATION", "MEDIUM", "127.0.0.1", "student_demo", "Simulated auth bypass with payload: ' OR '1'='1", "Safely bound as literal string parameter"),
        ("LOGIN_SUCCESS", "INFO", "127.0.0.1", "student_alice", "Student Alice authenticated with salted PBKDF2 hash match.", "Secure PBKDF2 hash verified"),
    ]
    for l in logs:
        cursor.execute(
            """INSERT INTO security_audit_logs 
               (event_type, severity, source_ip, username_attempted, description, defense_action_taken) 
               VALUES (?, ?, ?, ?, ?, ?);""",
            l
        )

    conn.commit()


# ============================================================================
# DEFENSIVE DATA ACCESS FUNCTIONS (100% Parameterized Queries)
# ============================================================================

def authenticate_user_defensively(username: str, password: str):
    """
    Performs secure authentication using parameterized queries and PBKDF2 verification.
    """
    conn = get_connection()
    cursor = conn.cursor()
    is_sqlite = (_active_engine == "SQLite")
    placeholder = "?" if is_sqlite else "%s"

    query = f"SELECT id, username, password_hash, salt, role FROM users WHERE username = {placeholder};"

    try:
        cursor.execute(query, (username,))
        row = cursor.fetchone()
        
        if row:
            stored_hash = row["password_hash"]
            stored_salt = row["salt"]
            role = row["role"]

            # Constant-time PBKDF2 verification
            if verify_password(password, stored_hash, stored_salt):
                return {
                    "success": True,
                    "role": role,
                    "username": username,
                    "message": "Authentication successful.",
                    "defense_explanation": "Query structure compiled beforehand. Payload treated purely as inert string data."
                }
    except Exception as e:
        # Defensive Error Handling: Log internally, never leak to client
        print(f"[SEC_AUDIT] Database query error: {e}")
    finally:
        conn.close()

    return {
        "success": False,
        "role": None,
        "username": username,
        "message": "Invalid username or password.",
        "defense_explanation": f"Parameterized query safely searched for literal value '{username}'. Attack payload neutralized."
    }


def save_quiz_attempt(student_name: str, student_id: str, score: int, total_questions: int, 
                      percentage: float, grade: str, time_taken_seconds: int, feedback_notes: str):
    """Saves student quiz attempt using a parameterized INSERT query."""
    conn = get_connection()
    cursor = conn.cursor()
    is_sqlite = (_active_engine == "SQLite")
    p = "?" if is_sqlite else "%s"

    query = f"""
        INSERT INTO quiz_attempts 
        (student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, feedback_notes)
        VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p});
    """

    try:
        cursor.execute(query, (
            student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, feedback_notes
        ))
        if is_sqlite:
            conn.commit()
        return True
    except Exception as e:
        print(f"[SEC_AUDIT] Error recording quiz attempt: {e}")
        return False
    finally:
        conn.close()


def get_recent_quiz_attempts(limit: int = 10):
    """Retrieves recent quiz leaderboard records using parameterized SELECT."""
    conn = get_connection()
    cursor = conn.cursor()
    is_sqlite = (_active_engine == "SQLite")
    p = "?" if is_sqlite else "%s"

    query = f"""
        SELECT student_name, student_id, score, total_questions, percentage, grade, time_taken_seconds, attempted_at 
        FROM quiz_attempts 
        ORDER BY attempted_at DESC 
        LIMIT {p};
    """

    try:
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            result.append({
                "student_name": r["student_name"],
                "student_id": r["student_id"],
                "score": r["score"],
                "total_questions": r["total_questions"],
                "percentage": round(float(r["percentage"]), 2),
                "grade": r["grade"],
                "time_taken_seconds": r["time_taken_seconds"],
                "attempted_at": str(r["attempted_at"])
            })
        return result
    except Exception as e:
        print(f"[SEC_AUDIT] Error fetching leaderboard: {e}")
        return []
    finally:
        conn.close()


def log_security_event(event_type: str, severity: str, source_ip: str, 
                       username_attempted: str, description: str, defense_action_taken: str):
    """Records security audit events using parameterized INSERT."""
    conn = get_connection()
    cursor = conn.cursor()
    is_sqlite = (_active_engine == "SQLite")
    p = "?" if is_sqlite else "%s"

    query = f"""
        INSERT INTO security_audit_logs 
        (event_type, severity, source_ip, username_attempted, description, defense_action_taken) 
        VALUES ({p}, {p}, {p}, {p}, {p}, {p});
    """

    try:
        cursor.execute(query, (
            event_type, severity, source_ip, username_attempted, description, defense_action_taken
        ))
        if is_sqlite:
            conn.commit()
        return True
    except Exception as e:
        print(f"[SEC_AUDIT] Failed to save audit log: {e}")
        return False
    finally:
        conn.close()


def get_recent_security_logs(limit: int = 20):
    """Retrieves recent security audit logs."""
    conn = get_connection()
    cursor = conn.cursor()
    is_sqlite = (_active_engine == "SQLite")
    p = "?" if is_sqlite else "%s"

    query = f"""
        SELECT event_type, severity, source_ip, username_attempted, description, defense_action_taken, created_at 
        FROM security_audit_logs 
        ORDER BY created_at DESC 
        LIMIT {p};
    """

    try:
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            result.append({
                "event_type": r["event_type"],
                "severity": r["severity"],
                "source_ip": r["source_ip"],
                "username_attempted": r["username_attempted"],
                "description": r["description"],
                "defense_action_taken": r["defense_action_taken"],
                "created_at": str(r["created_at"])
            })
        return result
    except Exception as e:
        print(f"[SEC_AUDIT] Failed to fetch audit logs: {e}")
        return []
    finally:
        conn.close()

"""
test_backend.py - Unit test suite for Python Defensive Database Security backend
"""

import sys
import database
import password_util
import input_validator

def run_tests():
    print(">>> Testing password hashing & verification...")
    salt = password_util.generate_salt()
    assert len(salt) == 64, f"Expected 64-char salt hex, got {len(salt)}"
    h = password_util.hash_password("Password@123", salt)
    assert len(h) == 64, f"Expected 64-char hash hex, got {len(h)}"
    assert password_util.verify_password("Password@123", h, salt) is True, "Password verification failed"
    assert password_util.verify_password("WrongPassword", h, salt) is False, "Wrong password accepted"
    print("[PASS] Password cryptography tests passed!")

    print(">>> Testing input validator...")
    assert input_validator.is_valid_username("student_alice") is True
    assert input_validator.is_valid_username("invalid user with space!") is False
    assert input_validator.contains_sqli_pattern("' OR '1'='1") is True
    assert input_validator.contains_sqli_pattern("normal_username") is False
    assert input_validator.escape_html("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    print("[PASS] Input validator tests passed!")

    print(">>> Testing database initialization & queries...")
    database.init_database()
    status = database.get_database_status()
    print(f"    Active Database: {status['engine']}")

    # Test authentication
    auth_alice = database.authenticate_user_defensively("student_alice", "Password@123")
    assert auth_alice["success"] is True, "Alice login failed"
    print("[PASS] Authentication test passed (student_alice)")

    # Test SQL injection attack payload against defensive authentication
    auth_attack = database.authenticate_user_defensively("' OR '1'='1", "any_pass")
    assert auth_attack["success"] is False, "SQL injection bypassed authentication!"
    print("[PASS] SQL Injection defense test passed: payload safely blocked by parameterized query!")

    # Test quiz saving
    saved = database.save_quiz_attempt("Test Student", "TEST-01", 10, 10, 100.0, "A+", 45, "Great work")
    assert saved is True, "Quiz attempt save failed"
    attempts = database.get_recent_quiz_attempts(5)
    assert len(attempts) > 0, "No quiz attempts retrieved"
    print(f"[PASS] Quiz leaderboard test passed ({len(attempts)} records retrieved)")

    # Test security audit logging
    logged = database.log_security_event("TEST_EVENT", "INFO", "127.0.0.1", "test_user", "Testing audit log", "Defense active")
    assert logged is True, "Audit log save failed"
    logs = database.get_recent_security_logs(5)
    assert len(logs) > 0, "No audit logs retrieved"
    print(f"[PASS] Security audit logs test passed ({len(logs)} records retrieved)")

    print("\n[COMPLETE] ALL BACKEND DEFENSIVE SECURITY TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_tests()

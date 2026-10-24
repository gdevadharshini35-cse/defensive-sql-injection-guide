"""
config.py - Defensive Database Security Configuration
Course: Value Added Course (VAC) in Cybersecurity & Secure Software Development
"""

import os

# Server Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

# MySQL Database Configuration
# Default settings connect to a local MySQL server (port 3306).
# Update DB_USER and DB_PASSWORD to match your local MySQL installation.
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_NAME = os.environ.get("DB_NAME", "db_security_vac")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "devadharshini")

# Local SQLite Fallback Database
# If MySQL is not running or not installed, the application automatically
# initializes and uses this local SQLite database so students can test immediately!
SQLITE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db_security_vac.db")

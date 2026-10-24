# Defensive Guide to SQL Injection and Database Security (Python Edition)

[![Language](https://img.shields.io/badge/Language-Python%203.10%2B%20%2F%203.12%2B-3776ab.svg)]()
[![Framework](https://img.shields.io/badge/Web%20Framework-Flask-000000.svg)]()
[![Database](https://img.shields.io/badge/Database-MySQL%20%2B%20SQLite%20Auto--Fallback-00b4d8.svg)]()
[![Defense](https://img.shields.io/badge/Security-DB--API%20Parameterization%20%26%20PBKDF2-10b981.svg)]()
[![Course](https://img.shields.io/badge/Course-Value%20Added%20Course%20(VAC)-0077b6.svg)]()

A complete, beginner-friendly, responsive educational web application titled **“Defensive Guide to SQL Injection and Database Security”** built with **Python 3**, **Flask**, **HTML5**, **CSS3**, **JavaScript**, and **MySQL / SQLite**.

Engineered specifically for college computer science students, academic project evaluations, and software developers to understand how SQL injection exploits happen and how to completely neutralize them using defensive coding standards in Python.

---

## 📋 Table of Contents
1. [Project Overview & Objective](#-project-overview--objective)
2. [Key Features Checklist](#-key-features-checklist)
3. [Technology Stack](#-technology-stack)
4. [Project Directory Layout](#-project-directory-layout)
5. [Prerequisites](#-prerequisites)
6. [Quick Start (How to Run)](#-quick-start-how-to-run)
7. [Running in IDEs (VS Code / PyCharm)](#-running-in-ides-vs-code--pycharm)
8. [MySQL Database Setup (Optional)](#-mysql-database-setup-optional)
9. [Zero-Setup SQLite Automatic Fallback](#-zero-setup-sqlite-automatic-fallback)
10. [Defensive Architecture: Parameterized Queries in Python](#-defensive-architecture-parameterized-queries-in-python)
11. [College Presentation & Viva Voce Q&A](#-college-presentation--viva-voce-qa)
12. [Ethical Cybersecurity Disclosure](#-ethical-cybersecurity-disclosure)

---

## 🎯 Project Overview & Objective

### Objective
The primary goal of this project is to educate students about SQL injection attacks and teach them how to protect databases using secure coding practices.

### Core Defensive Principle
SQL injection occurs when untrusted user data is directly concatenated or formatted into dynamic query strings. By implementing **DB-API Parameterized Queries** (`%s` in MySQL, `?` in SQLite), the database compiles the query syntax tree **before** binding user input. User data is treated purely as an inert literal, making code execution mathematically impossible.

---

## 🚀 Key Features Checklist

| # | Feature | Implementation Details |
|---|---|---|
| **1** | **Modern Cyber Home Page** | Cyber-themed design (Blue `#00b4d8`, Black `#070b14`, White `#ffffff`), threat statistics, quick module launch cards. |
| **2** | **SQL Injection Guide** | Explains what SQLi is, how string formatting creates exploits, attack types (In-Band, Blind/Inferential, Out-of-Band), and real-world impacts. |
| **3** | **Interactive Safe Simulator** | Real-time query playground testing 4 attack scenarios (Auth Bypass, UNION extraction, Comment Truncation, Numeric Tautology) side-by-side with zero external DB risk. |
| **4** | **Prevention Techniques** | Deep dives into 6 pillars: Parameterization, Dual-layer Validation, Safe Error Handling, Least Privilege (PoLP), Salted Password Hashing, and Whitelisting. |
| **5** | **Python Code Examples** | Tabbed syntax-highlighted code viewer contrasting vulnerable f-strings / string formatting with secure DB-API parameterized queries. |
| **6** | **Security Checklist & Gauge** | 12 interactive checkpoints with an animated circular SVG Readiness Score Gauge (0–100%), posture badges, and text audit report export. |
| **7** | **Assessment Quiz & Leaderboard** | 10 multiple-choice questions with real-time scoring, grade calculation (`A+`, `A`, `B`), in-depth question breakdowns, and live database leaderboard. |
| **8** | **About Project & Viva Notes** | System architecture diagrams, technology breakdown, key learning outcomes, and sample presentation viva voce questions & answers. |

---

## 💻 Technology Stack

- **Backend:** Python 3.10+ / 3.12+ (Flask, PyMySQL, built-in SQLite3, hashlib, hmac)
- **Frontend:** Responsive HTML5, Cyber CSS3 (Electric Blue, Deep Black, Crisp White), Vanilla JavaScript (ES6+). Zero external CDNs required.
- **Database Engine:** MySQL 8.0+ / MariaDB via PyMySQL, with automatic local SQLite3 fallback (`db_security_vac.db`).
- **Cryptography:** PBKDF2-HMAC-SHA256 (65,536 iterations, 32-byte cryptographically secure random salt, constant-time `hmac.compare_digest` verification).

---

## 📁 Project Directory Layout

```
Database security project/
├── app.py                       # Main Flask web application & REST API
├── config.py                    # Database connection settings & server port
├── database.py                  # Dual MySQL & SQLite database abstraction layer
├── password_util.py             # PBKDF2-HMAC-SHA256 password salting & verification
├── input_validator.py           # Server-side validation, regex whitelisting, XSS escape
├── requirements.txt             # Python dependencies (Flask, PyMySQL)
├── database.sql                 # MySQL setup script (schema, tables, seed data)
├── test_backend.py              # Automated backend defensive verification test suite
├── run.bat                      # 1-Click Windows execution script
├── run.ps1                      # 1-Click PowerShell execution script
├── README.md                    # Complete documentation & presentation guide
│
├── static/
│   ├── css/
│   │   └── style.css            # Cyber theme (Electric Blue, Deep Black, Crisp White)
│   └── js/
│       ├── app.js               # Tab navigation, API poller, code tabs, modal
│       ├── simulator.js         # Interactive safe SQLi vs Parameterized Query simulator
│       ├── checklist.js         # 12-item checklist, circular SVG gauge, report exporter
│       └── quiz.js              # 10-question quiz engine & live leaderboard
│
└── templates/
    └── index.html               # Main single-page web application template
```

---

## ⚙️ Prerequisites

1. **Python 3.10+ / 3.12+** installed on your system.
   - Verify by running in terminal:
     ```bash
     python --version
     ```
2. **Web Browser:** Google Chrome, Microsoft Edge, Firefox, or Safari.
3. *(Optional)* **MySQL Server:** Only required if you wish to connect to an external live MySQL server. If MySQL is not running, the application automatically uses the local SQLite database.

---

## 🏃 Quick Start (How to Run)

### Method 1: 1-Click Execution (Windows)
Simply double-click **`run.bat`** (or right-click `run.ps1` ➔ Run with PowerShell).  
The script automatically:
1. Detects Python.
2. Installs required dependencies (`Flask`, `pymysql`).
3. Starts the server and **automatically opens your web browser** to:
   ```
   http://127.0.0.1:5000/
   ```

### Method 2: Manual Terminal / Command Prompt
1. Open Command Prompt or PowerShell in this project folder:
   ```cmd
   cd "c:\Users\acer\Documents\Database security project"
   ```
2. Install dependencies:
   ```cmd
   pip install -r requirements.txt
   ```
3. Run the application:
   ```cmd
   python app.py
   ```
4. Open your browser and navigate to `http://127.0.0.1:5000/`.

---

## 🖥️ Running in IDEs (VS Code / PyCharm)

### In Visual Studio Code:
1. Open VS Code.
2. Click **File** ➔ **Open Folder...** and select `Database security project`.
3. Open `app.py`.
4. Press **F5** (or click the green **▷ Run Python File** button at the top-right).
5. The application will launch and open your default browser.

### In PyCharm:
1. Open PyCharm and select **Open**.
2. Select this project directory.
3. Right-click `app.py` ➔ **Run 'app'**.

---

## 🗄️ Zero-Setup SQLite Automatic Fallback

**Zero-Panic Presentation Guarantee:**
When presenting in a college classroom or viva evaluation where MySQL is not installed, **the application runs 100% smoothly**:
- The backend detects that MySQL is offline.
- It automatically creates and populates a local SQLite database (`db_security_vac.db`) with identical tables and pre-seeded accounts:
  - `student_alice` / `Password@123`
  - `student_bob` / `Student#2026`
  - `sec_admin` / `Admin#Secure99!`
- All 4 interactive simulations, the 12-item checklist, and the 10-question assessment quiz run seamlessly with real database persistence.

---

## 🐬 MySQL Database Setup (Optional)

To connect to a live MySQL server:
1. Open **MySQL Workbench** or **phpMyAdmin**.
2. Run `database.sql` to create `db_security_vac` and sample tables.
3. Open `config.py` and update your MySQL username and password:
   ```python
   DB_USER = "root"
   DB_PASSWORD = "your_mysql_password"
   ```
4. Restart `python app.py`. The navbar badge will update to **"🟢 MySQL Connected (Live)"**.

---

## 🔐 Defensive Architecture: Parameterized Queries in Python

### 1. Insecure Pattern vs. Secure Parameterized Pattern

#### ❌ Insecure Pattern (Vulnerable to SQL Injection)
```python
# DANGER: Directly interpolating untrusted input with f-strings!
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
user = cursor.fetchone()
```
- **Why it fails:** If an attacker enters `' OR '1'='1`, the string literal is closed early and `'1'='1'` becomes an active executable condition evaluated by the SQL engine, bypassing authentication.

#### ✅ Secure Defensive Pattern (Python DB-API Parameterization)
```python
# SECURE: '%s' (or '?' in SQLite) indicates a strict parameter placeholder
query = "SELECT password_hash, salt, role FROM users WHERE username = %s"

# Pass parameter values as a separate tuple:
cursor.execute(query, (username,))
user = cursor.fetchone()

if user:
    # Verify password with constant-time salted PBKDF2
    if verify_password(password, user["password_hash"], user["salt"]):
        return True
```
- **Why it succeeds:** The query template is compiled **before** receiving user data. When the driver sends `' OR '1'='1`, the database engine looks for a literal username equal to `"' OR '1'='1"`, neutralizing any code execution.

### 2. Password Security: Salted PBKDF2
- Plain-text passwords and fast algorithms (MD5, plain SHA-256) are strictly prohibited.
- Implemented in `password_util.py`:
  - Algorithm: `PBKDF2WithHmacSHA256`
  - Iterations: `65,536` rounds
  - Salt: 32-byte (256-bit) cryptographically secure random salt via `os.urandom(32)`
  - Verification: Constant-time comparison via `hmac.compare_digest` to prevent timing attacks.

---

## 🎓 College Presentation & Viva Voce Q&A

Use these questions and answers to prepare for your viva voce or project defense:

### Q1: What is the root cause of SQL Injection?
> **Answer:** SQL injection occurs when untrusted user input is directly concatenated or formatted into SQL command strings. The database parser cannot distinguish between developer instructions and user data.

### Q2: Why does a Parameterized Query solve SQL Injection when input escaping often fails?
> **Answer:** Escaping and blacklists fail because attackers constantly find new character encodings and comment tricks that bypass filters. Parameterized queries solve the problem architecturally: the database pre-compiles the query structure. Input values are sent separately as inert literal data, making it mathematically impossible for input to alter query syntax.

### Q3: In Python, why is an f-string in `cursor.execute()` dangerous even if you use `cursor.execute()`?
> **Answer:** Because an f-string (`f"SELECT ... {input}"`) evaluates and concatenates the string *in Python memory* before `cursor.execute()` ever sees it. The database driver receives an already-compromised raw SQL string. Parameterization requires passing the template and data tuple as separate arguments: `cursor.execute("SELECT ... %s", (input,))`.

### Q4: Can parameterized queries parameterize table names or column names?
> **Answer:** No. Parameter placeholders (`%s` / `?`) can only replace data values. Dynamic table names, column names, or sort orders (`ORDER BY`) must be validated against a strict, hardcoded in-code whitelist.

### Q5: Why is client-side validation alone insufficient for web security?
> **Answer:** Client-side JavaScript runs on the user's browser, which can be bypassed easily using tools like Postman, cURL, or proxy tools like Burp Suite. Server-side validation is mandatory.

---

## ⚖️ Ethical Cybersecurity Disclosure

This application is engineered strictly for **defensive cybersecurity education**, academic evaluation, and secure coding instruction. All interactive simulations run in an isolated memory space. Attempting injection attacks on systems without explicit, written authorization from the owner is illegal under cyber law. Always practice ethical computing.

---

**Developed for College Value Added Course (VAC) Project Submission**  
*Technologies: Python 3.12, Flask, PyMySQL, SQLite3, HTML5, CSS3, JavaScript ES6+*

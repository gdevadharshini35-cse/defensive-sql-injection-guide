/**
 * checklist.js - Interactive Database Security Checklist & Readiness Gauge
 * 
 * Provides an interactive security posture assessment tool allowing students
 * to evaluate database systems against OWASP and industry best practices.
 */

const Checklist = (() => {
  const STORAGE_KEY = "vac_db_security_checklist_v1";

  const checklistData = [
    {
      category: "Application Code Defense",
      icon: "💻",
      items: [
        {
          id: "chk_prepared_statements",
          title: "100% Parameterized Queries (PreparedStatement)",
          desc: "Every database query involving user input uses PreparedStatement with ? placeholders. Zero string concatenation.",
          weight: 12
        },
        {
          id: "chk_dual_input_validation",
          title: "Server-Side & Client-Side Input Validation",
          desc: "Rigorous server-side whitelisting, regex patterns, length limits, and type enforcement on all input fields.",
          weight: 8
        },
        {
          id: "chk_whitelist_dynamic_sql",
          title: "Strict Whitelisting for Dynamic Identifiers",
          desc: "Dynamic table or column names (e.g., ORDER BY, ASC/DESC) are checked against a hardcoded in-code whitelist.",
          weight: 8
        }
      ]
    },
    {
      category: "Database Access & Account Hardening",
      icon: "🛡️",
      items: [
        {
          id: "chk_least_privilege",
          title: "Principle of Least Privilege (PoLP) Enforced",
          desc: "Web application connects using a dedicated non-root user with only necessary DML rights (SELECT, INSERT, UPDATE).",
          weight: 10
        },
        {
          id: "chk_no_admin_privileges",
          title: "Destructive DDL & Admin Privileges Revoked",
          desc: "Application user account is explicitly denied DROP, ALTER, GRANT OPTION, FILE, and SUPER privileges.",
          weight: 8
        },
        {
          id: "chk_disable_remote_root",
          title: "Remote Database Root Access Disabled",
          desc: "Root database user is restricted to localhost ('root'@'localhost') and protected by a strong 20+ character secret.",
          weight: 8
        }
      ]
    },
    {
      category: "Authentication & Password Cryptography",
      icon: "🔐",
      items: [
        {
          id: "chk_salted_hashing",
          title: "Salted Adaptive Password Hashing (PBKDF2/BCrypt/Argon2)",
          desc: "Passwords are never stored in plain text or fast hashes (MD5/SHA1). High-iteration salted key derivation is used.",
          weight: 12
        },
        {
          id: "chk_account_lockout",
          title: "Rate Limiting & Account Lockout Defenses",
          desc: "Account lockout or exponential delay is triggered after 5 consecutive failed login attempts to prevent brute force.",
          weight: 7
        },
        {
          id: "chk_no_hardcoded_secrets",
          title: "Externalized Database Credentials",
          desc: "Database passwords are not hardcoded in source repositories; managed via environment variables or secret vaults.",
          weight: 9
        }
      ]
    },
    {
      category: "Error Handling, Logging & Network Defense",
      icon: "📡",
      items: [
        {
          id: "chk_generic_error_handling",
          title: "Suppression of Raw Database Errors & Stack Traces",
          desc: "Exceptions catch SQLException and present generic user notices. Internal details are never leaked to the browser.",
          weight: 10
        },
        {
          id: "chk_security_audit_logging",
          title: "Centralized Security Audit Logging",
          desc: "Authentication failures, privilege changes, and blocked injection attempts are recorded to secure audit logs.",
          weight: 8
        },
        {
          id: "chk_encrypted_connections",
          title: "TLS/SSL Encrypted Database Connections",
          desc: "Data-in-transit between the application server and database server is encrypted using TLS 1.3/1.2.",
          weight: 10
        }
      ]
    }
  ];

  function init() {
    renderChecklist();
    loadSavedState();
    updateScore();
    bindEvents();
  }

  function renderChecklist() {
    const container = document.getElementById("checklist-items-container");
    if (!container) return;

    container.innerHTML = checklistData.map(group => {
      const itemsHtml = group.items.map(item => `
        <label class="checklist-item" for="${item.id}">
          <input type="checkbox" id="${item.id}" class="checklist-checkbox" data-weight="${item.weight}">
          <div class="checklist-text">
            <div class="checklist-label">${item.title} <span style="font-size:0.75rem; color:var(--cyber-blue); font-weight:normal;">(+${item.weight} pts)</span></div>
            <div class="checklist-desc">${item.desc}</div>
          </div>
        </label>
      `).join("");

      return `
        <div class="checklist-group">
          <div class="checklist-group-title">
            <span>${group.icon}</span>
            <span>${group.category}</span>
          </div>
          ${itemsHtml}
        </div>
      `;
    }).join("");
  }

  function updateScore() {
    let currentScore = 0;
    let totalPossible = 0;
    let checkedCount = 0;
    let totalItems = 0;

    const checkboxes = document.querySelectorAll(".checklist-checkbox");
    checkboxes.forEach(cb => {
      const weight = parseInt(cb.getAttribute("data-weight") || "0", 10);
      totalPossible += weight;
      totalItems++;
      if (cb.checked) {
        currentScore += weight;
        checkedCount++;
      }
    });

    const percentage = totalPossible > 0 ? Math.round((currentScore / totalPossible) * 100) : 0;

    // Update Circular SVG Gauge
    const circle = document.getElementById("score-circle-progress");
    const valText = document.getElementById("score-gauge-val");
    const countText = document.getElementById("score-checked-count");
    const statusText = document.getElementById("posture-status-text");

    if (valText) valText.textContent = `${percentage}%`;
    if (countText) countText.textContent = `${checkedCount} of ${totalItems} Best Practices Verified`;

    // SVG dash calculations: circle radius = 60, circumference = 2 * PI * 60 ≈ 377
    if (circle) {
      const circumference = 377;
      const offset = circumference - (percentage / 100) * circumference;
      circle.style.strokeDashoffset = offset;

      // Color transitions based on readiness
      if (percentage >= 85) {
        circle.style.stroke = "var(--success-green)";
        if (statusText) {
          statusText.textContent = "🛡️ Hardened Fortress";
          statusText.style.color = "var(--success-green)";
        }
      } else if (percentage >= 60) {
        circle.style.stroke = "var(--cyber-cyan)";
        if (statusText) {
          statusText.textContent = "⚡ Moderate Defensive Posture";
          statusText.style.color = "var(--cyber-cyan)";
        }
      } else if (percentage >= 35) {
        circle.style.stroke = "var(--warning-amber)";
        if (statusText) {
          statusText.textContent = "⚠️ Significant Attack Surface";
          statusText.style.color = "var(--warning-amber)";
        }
      } else {
        circle.style.stroke = "var(--danger-red)";
        if (statusText) {
          statusText.textContent = "🚨 Critical Vulnerability Risk";
          statusText.style.color = "var(--danger-red)";
        }
      }
    }

    saveState();
  }

  function saveState() {
    const state = {};
    document.querySelectorAll(".checklist-checkbox").forEach(cb => {
      state[cb.id] = cb.checked;
    });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }

  function loadSavedState() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      // Default initial state: check 4 core best practices for demo
      ["chk_prepared_statements", "chk_dual_input_validation", "chk_least_privilege", "chk_generic_error_handling"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.checked = true;
      });
      return;
    }
    try {
      const state = JSON.parse(raw);
      Object.keys(state).forEach(id => {
        const el = document.getElementById(id);
        if (el) el.checked = !!state[id];
      });
    } catch (e) {
      console.warn("Could not load saved checklist state:", e);
    }
  }

  function selectAll(check) {
    document.querySelectorAll(".checklist-checkbox").forEach(cb => {
      cb.checked = check;
    });
    updateScore();
    App.showToast(check ? "All 12 defensive best practices enabled!" : "Checklist cleared.", "info");
  }

  function loadPreset(type) {
    if (type === "hardened") {
      selectAll(true);
    } else if (type === "vulnerable") {
      document.querySelectorAll(".checklist-checkbox").forEach(cb => cb.checked = false);
      // Check only minimal item
      const chk = document.getElementById("chk_dual_input_validation");
      if (chk) chk.checked = true;
      updateScore();
      App.showToast("Loaded Typical Legacy Vulnerable System Profile", "warning");
    }
  }

  function exportReport() {
    let report = "=================================================================\n";
    report += "  DATABASE SECURITY READINESS AUDIT REPORT\n";
    report += "  Project: Defensive Guide to SQL Injection and Database Security\n";
    report += "  Generated: " + new Date().toLocaleString() + "\n";
    report += "=================================================================\n\n";

    let passed = 0;
    let total = 0;

    checklistData.forEach(group => {
      report += `[SECTION: ${group.category.toUpperCase()}]\n`;
      group.items.forEach(item => {
        total++;
        const el = document.getElementById(item.id);
        const isOk = el && el.checked;
        if (isOk) passed++;
        report += `  ${isOk ? "[PASS ✓]" : "[FAIL ✗]"} ${item.title} (+${item.weight} pts)\n`;
        report += `           ${item.desc}\n`;
      });
      report += "\n";
    });

    const pct = Math.round((passed / total) * 100);
    report += "-----------------------------------------------------------------\n";
    report += `AUDIT SUMMARY: ${passed} of ${total} controls implemented (${pct}% Readiness)\n`;
    report += `DEFENSE POSTURE: ${pct >= 85 ? "HARDENED FORTRESS" : pct >= 60 ? "MODERATE DEFENSE" : "HIGH VULNERABILITY RISK"}\n`;
    report += "RECOMMENDATION: Enforce JDBC PreparedStatement across all queries and isolate database accounts.\n";
    report += "=================================================================\n";

    // Download file in browser
    const blob = new Blob([report], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "Database_Security_Audit_Report.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    App.showToast("Security Audit Report downloaded!", "success");
  }

  function bindEvents() {
    document.addEventListener("change", e => {
      if (e.target && e.target.classList.contains("checklist-checkbox")) {
        updateScore();
      }
    });

    const btnSelectAll = document.getElementById("btn-checklist-all");
    const btnReset = document.getElementById("btn-checklist-reset");
    const btnVulnerable = document.getElementById("btn-checklist-vulnerable");
    const btnExport = document.getElementById("btn-checklist-export");

    if (btnSelectAll) btnSelectAll.addEventListener("click", () => selectAll(true));
    if (btnReset) btnReset.addEventListener("click", () => selectAll(false));
    if (btnVulnerable) btnVulnerable.addEventListener("click", () => loadPreset("vulnerable"));
    if (btnExport) btnExport.addEventListener("click", exportReport);
  }

  return { init, selectAll, loadPreset, exportReport };
})();

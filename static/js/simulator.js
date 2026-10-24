/**
 * simulator.js - Safe Interactive SQL Injection vs PreparedStatement Simulator
 * 
 * STRICT DEFENSIVE COMPUTING POLICY:
 * This simulator is designed purely for educational cybersecurity training.
 * It visualizes the internal lexical parsing of SQL statements, contrasting
 * insecure dynamic string concatenation with secure PreparedStatement parameter binding.
 */

const Simulator = (() => {
  // Preset Attack Scenarios for College Demos
  const scenarios = {
    auth_bypass: {
      name: "Authentication Bypass",
      defaultUsername: "' OR '1'='1",
      defaultPassword: "any_password",
      description: "Uses a single quote to break out of the string literal and introduces an always-true tautology ('1'='1').",
      vulnerableTemplate: "SELECT * FROM users WHERE username = '{{USER}}' AND password = '{{PASS}}'",
      secureTemplate: "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?",
      payloadChips: ["' OR '1'='1", "' OR 1=1 --", "admin' --", "' OR ''='", "student_alice"]
    },
    union_select: {
      name: "UNION-Based Data Extraction",
      defaultUsername: "admin' UNION SELECT 999, 'infiltrator', 'hacked@edu', 'stolen_hash', 'salt', 'admin', 0, 0, NOW() -- ",
      defaultPassword: "demo",
      description: "Appends a UNION SELECT query to extract additional columns or records across database tables.",
      vulnerableTemplate: "SELECT id, username, email FROM users WHERE username = '{{USER}}'",
      secureTemplate: "SELECT id, username, email FROM users WHERE username = ?",
      payloadChips: ["admin' UNION SELECT 1, 'hacked', 'hacked@edu' --", "' UNION SELECT null, @@version, null --", "student_bob"]
    },
    comment_truncate: {
      name: "Comment Query Truncation",
      defaultUsername: "admin' -- ",
      defaultPassword: "wrong_password_ignored",
      description: "Uses the SQL comment sequence (-- or /* */) to truncate the query, completely eliminating password verification.",
      vulnerableTemplate: "SELECT * FROM users WHERE username = '{{USER}}' AND password = '{{PASS}}'",
      secureTemplate: "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?",
      payloadChips: ["admin' --", "admin' /*", "sec_admin' --", "student_alice"]
    },
    numeric_tautology: {
      name: "Numeric Parameter Injection",
      defaultUsername: "101 OR 1=1",
      defaultPassword: "N/A",
      description: "In numeric lookups (e.g., student_id = 101), no quotes are used. Any injected operator executes immediately as SQL code.",
      vulnerableTemplate: "SELECT student_name, grade FROM student_records WHERE id = {{USER}}",
      secureTemplate: "SELECT student_name, grade FROM student_records WHERE id = ?",
      payloadChips: ["101 OR 1=1", "101; DROP TABLE logs--", "102 OR 2=2", "101"]
    }
  };

  let currentScenarioKey = "auth_bypass";

  function init() {
    renderScenarioButtons();
    loadScenario(currentScenarioKey);
    bindEvents();
  }

  function renderScenarioButtons() {
    const container = document.getElementById("scenario-selector");
    if (!container) return;

    container.innerHTML = Object.keys(scenarios).map(key => {
      const s = scenarios[key];
      const activeClass = key === currentScenarioKey ? "active" : "";
      return `<button class="btn btn-outline btn-sm scenario-btn ${activeClass}" data-key="${key}">
                🛡️ ${s.name}
              </button>`;
    }).join("");

    container.querySelectorAll(".scenario-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        container.querySelectorAll(".scenario-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        loadScenario(btn.getAttribute("data-key"));
      });
    });
  }

  function loadScenario(key) {
    currentScenarioKey = key;
    const s = scenarios[key];
    const userField = document.getElementById("sim-username");
    const passField = document.getElementById("sim-password");
    const passGroup = document.getElementById("sim-pass-group");
    const descEl = document.getElementById("sim-scenario-desc");

    if (userField) userField.value = s.defaultUsername;
    if (passField) passField.value = s.defaultPassword;
    if (descEl) descEl.textContent = s.description;

    // Toggle password field visibility if numeric scenario
    if (passGroup) {
      passGroup.style.display = key === "numeric_tautology" ? "none" : "block";
    }

    renderPayloadChips(s.payloadChips);
    updateQueryVisualizations();
  }

  function renderPayloadChips(chips) {
    const chipsContainer = document.getElementById("payload-chips");
    if (!chipsContainer) return;

    chipsContainer.innerHTML = chips.map(chip => {
      return `<button type="button" class="payload-chip" data-chip="${escapeHtml(chip)}">${escapeHtml(chip)}</button>`;
    }).join("");

    chipsContainer.querySelectorAll(".payload-chip").forEach(c => {
      c.addEventListener("click", () => {
        const input = document.getElementById("sim-username");
        if (input) {
          input.value = c.getAttribute("data-chip");
          updateQueryVisualizations();
        }
      });
    });
  }

  function updateQueryVisualizations() {
    const username = (document.getElementById("sim-username")?.value || "").trim();
    const password = document.getElementById("sim-password")?.value || "";
    const s = scenarios[currentScenarioKey];

    // 1. Build Insecure Visual Query
    const insecureBox = document.getElementById("insecure-query-display");
    if (insecureBox) {
      let rawSql = s.vulnerableTemplate
        .replace("{{USER}}", `<span class="sql-injected">${escapeHtml(username)}</span>`)
        .replace("{{PASS}}", `<span class="sql-string">${escapeHtml(password)}</span>`);

      insecureBox.innerHTML = rawSql;
    }

    // 2. Build Secure Visual PreparedStatement
    const secureBox = document.getElementById("secure-query-display");
    if (secureBox) {
      secureBox.innerHTML = `
        <div><span class="sql-keyword">SQL Template (Pre-Compiled):</span></div>
        <div style="margin: 4px 0;"><span class="sql-string">${s.secureTemplate}</span></div>
        <div style="margin-top: 8px;"><span class="sql-keyword">Parameter Map (Data Binding Only):</span></div>
        <div>[param 1] = <span class="sql-param">"${escapeHtml(username)}"</span> (String literal, 0 executable syntax)</div>
      `;
    }
  }

  async function executeSimulation() {
    const username = (document.getElementById("sim-username")?.value || "").trim();
    const password = document.getElementById("sim-password")?.value || "";

    if (!username) {
      App.showToast("Please enter a username or payload to test.", "warning");
      return;
    }

    const testBtn = document.getElementById("btn-run-simulation");
    if (testBtn) {
      testBtn.disabled = true;
      testBtn.innerHTML = "⏳ Evaluating Query Safety...";
    }

    try {
      // Send evaluation request to Java backend
      const response = await fetch("/api/login-demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const result = await response.json();
      renderSimulationResults(result, username);
      App.showToast("Simulation test completed successfully!", "success");
    } catch (err) {
      console.warn("Backend offline, running in-memory fallback simulation:", err);
      // Fallback safe client-side calculation
      const fallbackResult = generateFallbackResult(username, password);
      renderSimulationResults(fallbackResult, username);
      App.showToast("Simulation evaluated in Safe Offline Mode.", "info");
    } finally {
      if (testBtn) {
        testBtn.disabled = false;
        testBtn.innerHTML = "⚡ Run Dual Security Execution Test";
      }
    }
  }

  function renderSimulationResults(res, userInput) {
    const insecureOutcome = document.getElementById("insecure-outcome");
    const secureOutcome = document.getElementById("secure-outcome");
    const analysisBox = document.getElementById("sim-analysis-box");

    const insecure = res.insecure_simulation || {};
    const secure = res.secure_defense || {};

    if (insecureOutcome) {
      const isBypassed = insecure.authentication_bypassed;
      insecureOutcome.className = "outcome-box insecure";
      insecureOutcome.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong>Vulnerable Outcome:</strong>
          <span class="badge ${isBypassed ? 'badge-insecure' : 'badge-warning'}">
            ${isBypassed ? '🚨 AUTHENTICATION BYPASSED' : '⚠️ HIGH VULNERABILITY RISK'}
          </span>
        </div>
        <p>${insecure.explanation || 'String concatenation conflated command syntax with user input.'}</p>
        <div style="margin-top:6px; font-size:0.8rem; color:#fca5a5;">
          <strong>Query Parser View:</strong> ${isBypassed ? 'WHERE condition evaluated to TRUE for all rows.' : 'Query parsed without parameter separation.'}
        </div>
      `;
    }

    if (secureOutcome) {
      const isGranted = secure.authentication_granted;
      secureOutcome.className = "outcome-box secure";
      secureOutcome.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong>Parameterized Query Outcome:</strong>
          <span class="badge ${isGranted ? 'badge-secure' : 'badge-info'}">
            ${isGranted ? '✅ AUTHENTICATED SAFELY' : '🛡️ ACCESS SAFELY DENIED'}
          </span>
        </div>
        <p>${secure.defense_explanation || 'Parameterized queries separated SQL commands from input data.'}</p>
        <div style="margin-top:6px; font-size:0.8rem; color:#a7f3d0;">
          <strong>Database Driver Behavior:</strong> Input was strictly treated as the exact string literal: <code>${escapeHtml(userInput)}</code>.
        </div>
      `;
    }

    if (analysisBox) {
      analysisBox.style.display = "block";
      const takeawayEl = document.getElementById("sim-takeaway-text");
      if (takeawayEl) {
        takeawayEl.textContent = res.key_takeaway || "Prepared statements mathematically eliminate SQL Injection by pre-compiling the query tree structure before user data is received.";
      }
    }
  }

  function generateFallbackResult(username, password) {
    const lower = username.toLowerCase();
    const bypassed = lower.includes("' or '1'='1") || lower.includes("' or 1=1") || lower.includes("admin' --");

    return {
      status: "success",
      insecure_simulation: {
        authentication_bypassed: bypassed,
        explanation: bypassed 
          ? "VULNERABILITY CONFIRMED: The single quote (') broke out of the string boundary, injecting an always-true logical condition ('1'='1'). The database parser evaluated the WHERE clause as TRUE, bypassing login!"
          : "String concatenation allows attackers to manipulate SQL semantics whenever single quotes or comment tokens are supplied."
      },
      secure_defense: {
        authentication_granted: username === "student_alice" && password === "Password@123",
        defense_explanation: "PreparedStatement bound the entire payload as a literal string parameter. The database searched for a literal user with that exact string, neutralizing any attack payload safely."
      },
      key_takeaway: "In the insecure pattern, user input became executable code. In the secure PreparedStatement pattern, user input remained strictly inert data."
    };
  }

  function bindEvents() {
    const userField = document.getElementById("sim-username");
    const passField = document.getElementById("sim-password");
    const runBtn = document.getElementById("btn-run-simulation");

    if (userField) userField.addEventListener("input", updateQueryVisualizations);
    if (passField) passField.addEventListener("input", updateQueryVisualizations);
    if (runBtn) runBtn.addEventListener("click", executeSimulation);
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
  }

  return { init, executeSimulation };
})();

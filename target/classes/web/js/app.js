/**
 * app.js - Main Application Controller
 * 
 * Manages:
 *  - Tab routing and navigation
 *  - System status polling & connection badges
 *  - Java code example tab switcher & copy-to-clipboard
 *  - Global toast notifications
 *  - Live security audit logs viewer
 */

const App = (() => {

  function init() {
    setupNavigation();
    setupCodeTabs();
    setupMobileMenu();
    checkSystemStatus();
    
    // Initialize components
    if (window.Simulator) Simulator.init();
    if (window.Checklist) Checklist.init();
    if (window.Quiz) Quiz.init();

    // Load initial route based on URL hash or default to home
    const initialRoute = window.location.hash ? window.location.hash.substring(1) : "home";
    navigateTo(initialRoute);

    // Setup periodic status refresh
    setInterval(checkSystemStatus, 15000);
  }

  function setupNavigation() {
    document.querySelectorAll("[data-target]").forEach(btn => {
      btn.addEventListener("click", e => {
        e.preventDefault();
        const target = btn.getAttribute("data-target");
        navigateTo(target);
      });
    });

    window.addEventListener("hashchange", () => {
      const hash = window.location.hash.substring(1);
      if (hash) navigateTo(hash);
    });
  }

  function navigateTo(sectionId) {
    const targetSection = document.getElementById(sectionId);
    if (!targetSection) {
      sectionId = "home";
    }

    // Hide all sections
    document.querySelectorAll(".section-content").forEach(sec => {
      sec.classList.remove("active");
    });

    // Show target section
    const activeSec = document.getElementById(sectionId);
    if (activeSec) {
      activeSec.classList.add("active");
    }

    // Update nav link active state
    document.querySelectorAll(".nav-item").forEach(item => {
      item.classList.remove("active");
      const btn = item.querySelector("button");
      if (btn && btn.getAttribute("data-target") === sectionId) {
        item.classList.add("active");
      }
    });

    // Close mobile menu if open
    const navLinks = document.querySelector(".nav-links");
    if (navLinks) navLinks.classList.remove("open");

    // Scroll to top
    window.scrollTo({ top: 0, behavior: "smooth" });
    window.location.hash = sectionId;
  }

  function setupCodeTabs() {
    document.querySelectorAll(".code-tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const viewer = btn.closest(".code-viewer");
        if (!viewer) return;

        viewer.querySelectorAll(".code-tab-btn").forEach(b => b.classList.remove("active"));
        viewer.querySelectorAll(".code-tab-pane").forEach(p => p.style.display = "none");

        btn.classList.add("active");
        const targetPaneId = btn.getAttribute("data-code-pane");
        const targetPane = document.getElementById(targetPaneId);
        if (targetPane) {
          targetPane.style.display = "block";
        }
      });
    });

    // Copy code button handler
    document.querySelectorAll(".btn-copy-code").forEach(btn => {
      btn.addEventListener("click", () => {
        const targetCodeId = btn.getAttribute("data-copy-target");
        const codeEl = document.getElementById(targetCodeId);
        if (codeEl) {
          navigator.clipboard.writeText(codeEl.innerText).then(() => {
            showToast("Java code copied to clipboard!", "success");
          }).catch(() => {
            showToast("Failed to copy code.", "warning");
          });
        }
      });
    });
  }

  function setupMobileMenu() {
    const toggle = document.querySelector(".mobile-toggle");
    const navLinks = document.querySelector(".nav-links");

    if (toggle && navLinks) {
      toggle.addEventListener("click", () => {
        navLinks.classList.toggle("open");
      });
    }
  }

  async function checkSystemStatus() {
    const badge = document.getElementById("system-status-badge");
    const badgeText = document.getElementById("status-text");

    try {
      const res = await fetch("/api/status");
      const data = await res.json();

      if (badge && badgeText) {
        if (data.database_connected) {
          badge.className = "status-badge";
          badgeText.textContent = "MySQL Connected (Live)";
          badge.title = "Connected to MySQL at: " + data.database_url;
        } else {
          badge.className = "status-badge offline";
          badgeText.textContent = "Safe Demo Mode (Offline)";
          badge.title = "Running in in-memory simulation mode. Start MySQL to enable live DB logging.";
        }
      }
    } catch (e) {
      if (badge && badgeText) {
        badge.className = "status-badge offline";
        badgeText.textContent = "Standalone Offline Mode";
      }
    }
  }

  async function viewAuditLogs() {
    try {
      const res = await fetch("/api/audit-logs");
      const data = await res.json();
      const logs = data.logs || [];

      let logHtml = logs.map(l => `
        <tr>
          <td><span class="badge ${l.severity === 'CRITICAL' || l.severity === 'HIGH' ? 'badge-insecure' : l.severity === 'MEDIUM' ? 'badge-warning' : 'badge-secure'}">${escapeHtml(l.severity)}</span></td>
          <td><code>${escapeHtml(l.event_type)}</code></td>
          <td>${escapeHtml(l.username_attempted)}</td>
          <td>${escapeHtml(l.description)}</td>
          <td style="color:var(--cyber-cyan); font-size:0.8rem;">${escapeHtml(l.defense_action_taken)}</td>
          <td style="color:var(--text-muted); font-size:0.75rem;">${escapeHtml(l.created_at)}</td>
        </tr>
      `).join("");

      if (logs.length === 0) {
        logHtml = `<tr><td colspan="6" style="text-align:center;">No audit logs recorded yet.</td></tr>`;
      }

      const modalBody = document.getElementById("audit-modal-body");
      if (modalBody) {
        modalBody.innerHTML = logHtml;
      }
      openModal("audit-modal");
    } catch (e) {
      showToast("Could not load audit logs.", "warning");
    }
  }

  function openModal(id) {
    const m = document.getElementById(id);
    if (m) m.style.display = "flex";
  }

  function closeModal(id) {
    const m = document.getElementById(id);
    if (m) m.style.display = "none";
  }

  function showToast(message, type = "info") {
    let container = document.querySelector(".toast-container");
    if (!container) {
      container = document.createElement("div");
      container.className = "toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = "toast";

    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "warning") icon = "⚠️";
    if (type === "error") icon = "🚨";

    toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.toString()
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
  }

  return { init, navigateTo, showToast, viewAuditLogs, openModal, closeModal };
})();

document.addEventListener("DOMContentLoaded", App.init);

/**
 * quiz.js - Interactive Cybersecurity & SQL Injection Quiz Engine
 * 
 * Features:
 *  - 10 College-Level Value Added Course Evaluation Questions
 *  - Instant local grading + secure server-side verification via Java API
 *  - In-depth educational explanations for every question
 *  - Persistent student quiz attempts & leaderboard connected to MySQL
 */

const Quiz = (() => {
  const questions = [
    {
      id: 1,
      question: "What is the primary root cause of SQL Injection vulnerabilities?",
      options: [
        "Using MySQL instead of Oracle Database",
        "Concatenating untrusted user input directly into SQL command strings",
        "Not installing an antivirus program on the database server",
        "Having slow network bandwidth between client and server"
      ],
      correctIndex: 1,
      explanation: "SQL Injection occurs when user-supplied input is directly concatenated into SQL queries. The SQL engine cannot distinguish where developer instructions end and user data begins."
    },
    {
      id: 2,
      question: "Why does a PreparedStatement effectively eliminate SQL Injection?",
      options: [
        "It encrypts the entire hard drive holding the database files",
        "It blocks users from typing punctuation marks like apostrophes",
        "The database compiles query structure beforehand and treats user input strictly as literal data",
        "It hides the SQL database port behind a corporate firewall"
      ],
      correctIndex: 2,
      explanation: "PreparedStatement compiles the SQL statement into an execution plan first. When parameters are bound with ? markers, the database driver passes values strictly as data, never as executable SQL code."
    },
    {
      id: 3,
      question: "Which symbol is used as a parameter placeholder in JDBC PreparedStatements?",
      options: [
        "Hash symbol (#)",
        "At symbol (@)",
        "Question mark (?)",
        "Colon variable (:var)"
      ],
      correctIndex: 2,
      explanation: "Standard JDBC uses the question mark (?) as the parameter marker, which is bound via methods like ps.setString(1, val)."
    },
    {
      id: 4,
      question: "Why is client-side JavaScript validation insufficient on its own for security?",
      options: [
        "JavaScript runs slower than compiled Java code",
        "Attackers can easily bypass browser validation using proxy tools, cURL, or scripts",
        "HTML forms cannot send POST requests over HTTP",
        "Modern web browsers disable JavaScript by default"
      ],
      correctIndex: 1,
      explanation: "Client-side validation exists for user experience, but can be trivially bypassed by sending HTTP requests directly. Server-side validation is non-negotiable."
    },
    {
      id: 5,
      question: "Why should database error messages never be displayed directly to web application users?",
      options: [
        "They reveal database table names, column structures, and SQL syntax to attackers",
        "Displaying errors causes the database server to shut down immediately",
        "Errors make the website consume too much network bandwidth",
        "Web browsers cannot render SQL error strings"
      ],
      correctIndex: 0,
      explanation: "Detailed database errors (Error-based SQLi) leak sensitive architectural details to attackers. Applications should log errors internally and show a generic error message to users."
    },
    {
      id: 6,
      question: "What does the Principle of Least Privilege (PoLP) dictate for database accounts?",
      options: [
        "Every database user must be granted administrative ROOT privileges",
        "The web app database user should only have permissions strictly necessary for its tasks (e.g. SELECT, INSERT, UPDATE)",
        "Passwords should be shared across all developers to minimize accounts",
        "All database tables must be deleted after each session"
      ],
      correctIndex: 1,
      explanation: "If an attacker breaches a query, least privilege limits the blast radius. A restricted web app account should never have DROP, ALTER, GRANT, or FILE permissions."
    },
    {
      id: 7,
      question: "Why should passwords NEVER be stored using plain MD5 or SHA-1 hashes?",
      options: [
        "MD5 and SHA-1 hashes take up too much storage space in the database",
        "They are fast to compute and highly susceptible to precomputed Rainbow Table and GPU brute-force attacks",
        "MySQL cannot store alphanumeric hash strings",
        "MD5 hashes expire after 30 days automatically"
      ],
      correctIndex: 1,
      explanation: "MD5 and SHA-1 are cryptographically broken for passwords. Modern applications must use salted, adaptive key-derivation algorithms like PBKDF2, BCrypt, or Argon2id."
    },
    {
      id: 8,
      question: "What is the purpose of adding a unique 'Salt' to each password before hashing?",
      options: [
        "It compresses the password so the database loads faster",
        "It ensures that identical passwords produce completely unique hashes, preventing Rainbow Table attacks",
        "It allows database administrators to reverse-engineer passwords if forgotten",
        "It converts plain text into human-readable English words"
      ],
      correctIndex: 1,
      explanation: "A cryptographic salt ensures two users with the exact same password have totally different stored hashes, rendering precomputed lookup tables completely useless."
    },
    {
      id: 9,
      question: "Which type of SQL Injection relies on observing database response delays (e.g. SLEEP)?",
      options: [
        "In-Band UNION-based SQL Injection",
        "Time-Based Blind SQL Injection",
        "Error-based Verbose SQL Injection",
        "Out-of-Band DNS Exfiltration"
      ],
      correctIndex: 1,
      explanation: "When the application does not return data or errors, attackers inject sleep/delay commands to infer whether a boolean condition is true based on server response latency."
    },
    {
      id: 10,
      question: "Can PreparedStatements parameterize dynamic SQL table names or column names?",
      options: [
        "Yes, PreparedStatement ? markers work on table and column names without restriction",
        "No, table and column identifiers cannot be parameterized and must be validated against a strict whitelist",
        "Yes, but only if the user has database administrator rights",
        "Only when using Oracle databases, not MySQL"
      ],
      correctIndex: 1,
      explanation: "PreparedStatements only parameterize values (data literals). Dynamic column or table names must be strictly validated against a hardcoded whitelist of allowed identifier strings."
    }
  ];

  let userAnswers = {};
  let currentQuestionIndex = 0;
  let timerInterval = null;
  let secondsElapsed = 0;

  function init() {
    userAnswers = {};
    currentQuestionIndex = 0;
    secondsElapsed = 0;
    renderQuestion(0);
    startTimer();
    bindEvents();
    fetchLeaderboard();
  }

  function startTimer() {
    clearInterval(timerInterval);
    const timerEl = document.getElementById("quiz-timer-display");
    timerInterval = setInterval(() => {
      secondsElapsed++;
      const mins = Math.floor(secondsElapsed / 60);
      const secs = secondsElapsed % 60;
      if (timerEl) {
        timerEl.textContent = `${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
      }
    }, 1000);
  }

  function renderQuestion(idx) {
    currentQuestionIndex = idx;
    const q = questions[idx];
    const container = document.getElementById("quiz-question-container");
    const progressFill = document.getElementById("quiz-progress-fill");
    const counterText = document.getElementById("quiz-counter-text");
    const prevBtn = document.getElementById("btn-quiz-prev");
    const nextBtn = document.getElementById("btn-quiz-next");
    const submitBtn = document.getElementById("btn-quiz-submit");

    if (!container || !q) return;

    if (progressFill) {
      progressFill.style.width = `${((idx + 1) / questions.length) * 100}%`;
    }
    if (counterText) {
      counterText.textContent = `Question ${idx + 1} of ${questions.length}`;
    }

    const selectedOption = userAnswers[q.id];

    const optionsHtml = q.options.map((opt, optIdx) => {
      const isSelected = selectedOption === opt;
      return `
        <button type="button" class="option-btn ${isSelected ? 'selected' : ''}" data-qid="${q.id}" data-val="${escapeHtml(opt)}">
          <span class="option-indicator">${String.fromCharCode(65 + optIdx)}</span>
          <span>${escapeHtml(opt)}</span>
        </button>
      `;
    }).join("");

    container.innerHTML = `
      <div class="question-card">
        <h3 class="question-text">${idx + 1}. ${escapeHtml(q.question)}</h3>
        <div class="options-list">
          ${optionsHtml}
        </div>
      </div>
    `;

    // Bind option click
    container.querySelectorAll(".option-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        container.querySelectorAll(".option-btn").forEach(b => b.classList.remove("selected"));
        btn.classList.add("selected");
        const val = btn.getAttribute("data-val");
        userAnswers[q.id] = val;
        updateNavButtons();
      });
    });

    updateNavButtons();
  }

  function updateNavButtons() {
    const prevBtn = document.getElementById("btn-quiz-prev");
    const nextBtn = document.getElementById("btn-quiz-next");
    const submitBtn = document.getElementById("btn-quiz-submit");

    if (prevBtn) prevBtn.disabled = currentQuestionIndex === 0;

    const isLast = currentQuestionIndex === questions.length - 1;
    if (nextBtn) nextBtn.style.display = isLast ? "none" : "inline-flex";
    if (submitBtn) submitBtn.style.display = isLast ? "inline-flex" : "none";
  }

  function nextQuestion() {
    if (currentQuestionIndex < questions.length - 1) {
      renderQuestion(currentQuestionIndex + 1);
    }
  }

  function prevQuestion() {
    if (currentQuestionIndex > 0) {
      renderQuestion(currentQuestionIndex - 1);
    }
  }

  async function submitQuiz() {
    clearInterval(timerInterval);

    const answeredCount = Object.keys(userAnswers).length;
    if (answeredCount < questions.length) {
      if (!confirm(`You have answered ${answeredCount} of ${questions.length} questions. Submit anyway?`)) {
        return;
      }
    }

    const studentNameInput = document.getElementById("quiz-student-name");
    const studentIdInput = document.getElementById("quiz-student-id");
    const studentName = (studentNameInput?.value || "Student").trim();
    const studentId = (studentIdInput?.value || "VAC-STUDENT").trim();

    // Prepare payload for backend
    const payload = {
      student_name: studentName,
      student_id: studentId,
      time_taken: secondsElapsed.toString()
    };
    questions.forEach(q => {
      payload[`q${q.id}`] = userAnswers[q.id] || "";
    });

    const submitBtn = document.getElementById("btn-quiz-submit");
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = "⏳ Evaluating Answers Defensively...";
    }

    try {
      // Submit to Java backend
      const response = await fetch("/api/quiz", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      displayQuizResults(data);
      fetchLeaderboard();
      App.showToast("Quiz submitted and evaluated successfully!", "success");
    } catch (err) {
      console.warn("Backend offline, evaluating quiz locally:", err);
      // Fallback local evaluation
      const localResult = evaluateLocally(studentName, studentId);
      displayQuizResults(localResult);
      App.showToast("Quiz evaluated in Safe Offline Mode.", "info");
    }
  }

  function evaluateLocally(studentName, studentId) {
    let score = 0;
    const review = [];

    questions.forEach(q => {
      const correct = q.options[q.correctIndex];
      const submitted = userAnswers[q.id] || "(Not Answered)";
      const isCorrect = submitted === correct;
      if (isCorrect) score++;

      review.push({
        question_id: q.id,
        question: q.question,
        submitted_answer: submitted,
        correct_answer: correct,
        is_correct: isCorrect,
        explanation: q.explanation
      });
    });

    const total = questions.length;
    const pct = Math.round(((score / total) * 100) * 100) / 100;
    const grade = pct >= 90 ? "A+" : pct >= 80 ? "A" : pct >= 70 ? "B" : pct >= 60 ? "C" : "Needs Review";

    return {
      status: "success",
      student_name: studentName,
      student_id: studentId,
      score: score,
      total_questions: total,
      percentage: pct,
      grade: grade,
      time_taken_seconds: secondsElapsed,
      feedback: pct >= 80 ? "Excellent understanding of database security!" : "Good effort. Review PreparedStatement concepts.",
      review: review
    };
  }

  function displayQuizResults(res) {
    const quizWrapper = document.getElementById("quiz-active-wrapper");
    const resultsContainer = document.getElementById("quiz-results-container");

    if (quizWrapper) quizWrapper.style.display = "none";
    if (!resultsContainer) return;

    resultsContainer.style.display = "block";

    const isPass = res.percentage >= 70;
    const badgeClass = isPass ? "badge-secure" : "badge-insecure";

    let reviewHtml = (res.review || []).map((r, i) => `
      <div class="review-item ${r.is_correct ? 'correct' : 'incorrect'}">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <strong>Question ${i + 1}: ${escapeHtml(r.question)}</strong>
          <span class="badge ${r.is_correct ? 'badge-secure' : 'badge-insecure'}">
            ${r.is_correct ? '✓ Correct' : '✗ Incorrect'}
          </span>
        </div>
        <div style="font-size:0.875rem; margin-bottom:4px;">
          Your Answer: <strong style="color:${r.is_correct ? 'var(--success-green)' : 'var(--danger-red)'};">${escapeHtml(r.submitted_answer)}</strong>
        </div>
        ${!r.is_correct ? `<div style="font-size:0.875rem; color:var(--success-green); margin-bottom:4px;">Correct Answer: <strong>${escapeHtml(r.correct_answer)}</strong></div>` : ''}
        <div class="explanation-callout">
          <strong>Defensive Concept:</strong> ${escapeHtml(r.explanation)}
        </div>
      </div>
    `).join("");

    resultsContainer.innerHTML = `
      <div class="quiz-results-card">
        <span class="badge ${badgeClass}" style="margin-bottom:1rem; font-size:0.85rem; padding:0.4rem 0.9rem;">
          ${isPass ? '🏆 EVALUATION PASSED' : '📚 REVIEW RECOMMENDED'}
        </span>
        <div class="result-score-badge">${res.score} / ${res.total_questions}</div>
        <h2 style="font-size:1.5rem; margin-bottom:0.5rem; color:var(--text-white);">
          Performance: ${res.percentage}% (${res.grade})
        </h2>
        <p style="color:var(--text-muted); max-width:600px; margin:0 auto 1.5rem auto;">
          Candidate: <strong>${escapeHtml(res.student_name)}</strong> (${escapeHtml(res.student_id)}) | Time Taken: ${res.time_taken_seconds}s
        </p>
        <p style="color:var(--cyber-cyan); font-weight:600; margin-bottom:2rem;">
          ${escapeHtml(res.feedback)}
        </p>
        
        <div style="display:flex; justify-content:center; gap:1rem; flex-wrap:wrap; margin-bottom:2.5rem;">
          <button type="button" class="btn btn-primary" id="btn-quiz-retake">
            🔄 Retake Quiz
          </button>
          <button type="button" class="btn btn-outline" onclick="App.navigateTo('code-examples')">
            💻 Review Java PreparedStatement Code
          </button>
        </div>

        <h3 style="text-align:left; margin-bottom:1.25rem; color:var(--cyber-cyan); border-bottom:1px solid var(--border-subtle); padding-bottom:0.5rem;">
          Detailed Question Breakdown & Explanations:
        </h3>
        <div>
          ${reviewHtml}
        </div>
      </div>
    `;

    const retakeBtn = document.getElementById("btn-quiz-retake");
    if (retakeBtn) {
      retakeBtn.addEventListener("click", () => {
        resultsContainer.style.display = "none";
        if (quizWrapper) quizWrapper.style.display = "block";
        init();
      });
    }
  }

  async function fetchLeaderboard() {
    const tableBody = document.getElementById("leaderboard-body");
    if (!tableBody) return;

    try {
      const res = await fetch("/api/quiz");
      const data = await res.json();
      const list = data.leaderboard || [];

      if (list.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No quiz submissions yet. Be the first to complete the quiz!</td></tr>`;
        return;
      }

      tableBody.innerHTML = list.map((item, idx) => `
        <tr>
          <td><strong style="color:var(--cyber-cyan);">#${idx + 1}</strong></td>
          <td>${escapeHtml(item.student_name || 'Anonymous')}</td>
          <td><code>${escapeHtml(item.student_id || 'N/A')}</code></td>
          <td><strong>${item.score} / ${item.total_questions}</strong></td>
          <td><span class="badge ${item.percentage >= 80 ? 'badge-secure' : 'badge-warning'}">${item.percentage}% (${item.grade})</span></td>
          <td style="color:var(--text-muted); font-size:0.8rem;">${escapeHtml(item.attempted_at || 'Recent')}</td>
        </tr>
      `).join("");
    } catch (e) {
      console.warn("Could not fetch live leaderboard:", e);
    }
  }

  function bindEvents() {
    const prevBtn = document.getElementById("btn-quiz-prev");
    const nextBtn = document.getElementById("btn-quiz-next");
    const submitBtn = document.getElementById("btn-quiz-submit");

    if (prevBtn) prevBtn.addEventListener("click", prevQuestion);
    if (nextBtn) nextBtn.addEventListener("click", nextQuestion);
    if (submitBtn) submitBtn.addEventListener("click", submitQuiz);
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

  return { init, fetchLeaderboard };
})();

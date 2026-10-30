/**
 * Pragmatic Bug Detection & Highlighting System — Client Application
 * Implements core principles from "The Pragmatic Programmer" by David Thomas & Andrew Hunt:
 * 1. Problem Solving (Tracer Bullets, Don't Assume - Prove It)
 * 2. Clean Coding (DRY, Broken Windows Index, Orthogonality)
 * 3. Software Design (Design by Contract - Pre/Post/Invariants, Crash Early)
 * 4. Testing (Ruthless Testing, Ochiai SBFL, Closed-Loop Verifier)
 * 5. Code Maintenance (Refactor Early & Often, ETC Principle)
 * 6. Ubiquitous Automation (Single-click pipelines, SARIF v2.1.0)
 */

document.addEventListener("DOMContentLoaded", () => {
    initThemeSelector();
    initTabs();
    initLineNumbers();
    initSampleButtons();
    initCatalogToggle();
    loadCatalogRules();
    initCheckPlugButtons();
    initAgansProtocol();
    loadPragmaticPrinciples();

    // Default sample load: Pragmatic Contract & Clean Coding Sample
    loadSampleCode("pragmatic");
    loadSampleNetlist();
});

// ── Theme Selector ──────────────────────────────────────────────────────────
function initThemeSelector() {
    const select = document.getElementById("theme-select");
    if (!select) return;

    const savedTheme = localStorage.getItem("bug_detector_theme") || "theme-light";
    applyTheme(savedTheme);
    select.value = savedTheme;

    select.addEventListener("change", (e) => {
        const theme = e.target.value;
        applyTheme(theme);
        localStorage.setItem("bug_detector_theme", theme);
    });
}

function applyTheme(themeName) {
    document.body.classList.remove("theme-slate", "theme-navy", "theme-light", "theme-black");
    if (themeName && themeName !== "theme-light") {
        document.body.classList.add(themeName);
    } else {
        document.body.classList.add("theme-light");
    }
}

// ── Tab Management ──────────────────────────────────────────────────────────
function initTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

            tab.classList.add("active");
            const targetId = tab.getAttribute("data-tab");
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) targetPanel.classList.add("active");
        });
    });

    // Clicking header broken windows badge jumps to Pragmatic tab
    const bwBadge = document.getElementById("badge-broken-windows");
    if (bwBadge) {
        bwBadge.addEventListener("click", () => {
            const tabPragmatic = document.querySelector('.tab-btn[data-tab="tab-pragmatic"]');
            if (tabPragmatic) tabPragmatic.click();
        });
    }
}

// ── Line Number Sync ────────────────────────────────────────────────────────
function initLineNumbers() {
    const codeEditor = document.getElementById("code-editor");
    const codeGutter = document.getElementById("code-gutter");

    const netlistEditor = document.getElementById("netlist-editor");
    const netlistGutter = document.getElementById("netlist-gutter");

    function updateGutter(editor, gutter) {
        if (!editor || !gutter) return;
        const lines = editor.value.split("\n").length;
        let numbers = "";
        for (let i = 1; i <= lines; i++) {
            numbers += i + "\n";
        }
        gutter.textContent = numbers;
    }

    if (codeEditor && codeGutter) {
        codeEditor.addEventListener("input", () => updateGutter(codeEditor, codeGutter));
        codeEditor.addEventListener("scroll", () => {
            codeGutter.scrollTop = codeEditor.scrollTop;
        });
        updateGutter(codeEditor, codeGutter);
    }

    if (netlistEditor && netlistGutter) {
        netlistEditor.addEventListener("input", () => updateGutter(netlistEditor, netlistGutter));
        netlistEditor.addEventListener("scroll", () => {
            netlistGutter.scrollTop = netlistEditor.scrollTop;
        });
        updateGutter(netlistEditor, netlistGutter);
    }
}

// ── Sample Code & Netlists ──────────────────────────────────────────────────
const SAMPLES = {
    pragmatic: `"""
Pragmatic Programmer Benchmark: Clean Coding, Design by Contract & Broken Windows
Reference: The Pragmatic Programmer (Thomas & Hunt) - Topics 3, 9, 23, 24, 47
"""

class SensorStreamManager:
    def __init__(self, node_id: str):
        self.node_id = node_id
        # Allocate hardware communication buffer
        self.buffer = allocate_buffer(4096)
        self.is_active = True
        self.cache = {}

    def compute_transmission_rate(self, total_bytes: int, elapsed_seconds: float) -> float:
        # Precondition Violation: Caller failed to ensure elapsed_seconds != 0
        # Pragmatic Tip 37: Design with Contracts (require: elapsed_seconds > 0)
        # Pragmatic Tip 38: Dead Programs Tell No Lies (crash early)
        rate_mbps = (total_bytes * 8) / elapsed_seconds
        return rate_mbps

    def query_audit_telemetry(self, untrusted_filter: str):
        # Clean Coding Violation: Unsanitized input concatenated into sink
        # Pragmatic Tip 14: Eliminate Effects Between Unrelated Things (Orthogonality)
        sql_stmt = "SELECT * FROM node_audit WHERE filter = '" + untrusted_filter + "'"
        return execute(sql_stmt)

    def shutdown(self, emergency_purge: bool = False):
        if self.is_active:
            free_buf(self.buffer)
            self.is_active = False

        # Invariant Violation: Use-After-Free of deallocated pointer
        # Pragmatic Tip 3: Don't Live with Broken Windows
        # Pragmatic Tip 35: Finish What You Start
        process(self.buffer)

    def fetch_cached_metric(self, key):
        # Clean Coding Smell: Bare comparison with None
        if key == None:
            return "KEY_UNSET"
        return self.cache.get(key)
`,
    python: `import os

def process_packet(data):
    # Allocate packet buffer
    buf = allocate_buffer(1024)
    
    # Unsanitized user input -> SQL Query
    user_input = input("Enter filter parameter: ")
    query = "SELECT * FROM packets WHERE filter = '" + user_input + "'"
    
    length = len(data)
    divisor = 0
    # Unchecked division by zero
    ratio = length / divisor
    
    if length > 1500:
        free_buf(buf)
    
    # Use-After-Free: buffer passed after conditional deallocation
    process(buf)
    
    # Off-by-one array index boundary overflow
    results = []
    for i in range(length):
        if data[i] == data[i + 1]:
            results.append(i)
            
    return results

def append_item(val, target_list=[]):
    """Mutable default argument bug."""
    target_list.append(val)
    return target_list

def check_status(val):
    # Identity check with None bug
    if val == None:
        return "Not set"
    return "Valid"

def worker_thread(shared_counter):
    # Data race on shared variable without mutex lock
    shared_counter += 1
`,
    c: `#include <stdio.h>
#include <stdlib.h>

void handle_connection(int sock) {
    char *session = (char *)malloc(256);
    int count = 0;
    
    // Division by zero (Precondition breach)
    int rate = 100 / count;
    
    if (sock < 0) {
        free(session);
    }
    
    // Use-After-Free: session dereferenced after free (Invariant breach)
    session[0] = 'A';
    
    // Buffer overflow: off-by-one boundary
    int arr[10];
    for (int i = 0; i <= 10; i++) {
        arr[i] = i * 2;
    }
}
`,
};

const SAMPLE_NETLIST = {
    "module": "core_alu",
    "gates": [
        {"id": "FF_Launch", "type": "DFF", "clock_domain": "CLK_A", "delay_ns": 0.0, "clk_to_q_ns": 0.18, "setup_ns": 0.12, "hold_ns": 0.05},
        {"id": "AND2_U1", "type": "AND", "clock_domain": "CLK_A", "delay_ns": 0.15},
        {"id": "LUT6_U2", "type": "LUT", "clock_domain": "CLK_A", "delay_ns": 0.28},
        {"id": "CARRY8_U4", "type": "CARRY", "clock_domain": "CLK_A", "delay_ns": 0.45},
        {"id": "LUT6_MUX", "type": "MUX", "clock_domain": "CLK_A", "delay_ns": 0.22},
        {"id": "FF_Capture", "type": "DFF", "clock_domain": "CLK_B", "delay_ns": 0.0, "clk_to_q_ns": 0.18, "setup_ns": 0.12, "hold_ns": 0.05}
    ],
    "nets": [
        {"name": "data_bus_n0", "drivers": ["AND2_U1"], "sinks": ["LUT6_U2"], "bbox": ["M2", 50, 30, 120, 45]},
        {"name": "alu_carry_n7", "drivers": ["CARRY8_U4"], "sinks": ["LUT6_MUX"], "bbox": ["M3", 142.4, 88.0, 219.6, 104.2]},
        {"name": "floating_ctrl", "drivers": [], "sinks": ["AND2_U1"], "bbox": ["M1", 10, 10, 30, 20]}
    ],
    "timing_paths": [
        {
            "launch_ff": "FF_Launch",
            "capture_ff": "FF_Capture",
            "comb_cone": ["AND2_U1", "LUT6_U2", "CARRY8_U4", "LUT6_MUX"],
            "clk_period_ns": 2.0,
            "lnch_clk_delay_ns": 0.10,
            "cap_clk_delay_ns": 0.15,
            "uncertainty_ns": 0.05,
            "crossing_net": "alu_carry_n7",
            "vcd_window_ps": [18420, 18980],
            "bbox": ["M3", 142.4, 88.0, 219.6, 104.2]
        }
    ]
};

function loadSampleCode(type) {
    const editor = document.getElementById("code-editor");
    const gutter = document.getElementById("code-gutter");
    if (!editor) return;

    editor.value = SAMPLES[type] || SAMPLES.pragmatic;
    if (gutter) {
        const lines = editor.value.split("\n").length;
        let numbers = "";
        for (let i = 1; i <= lines; i++) numbers += i + "\n";
        gutter.textContent = numbers;
    }
}

function loadSampleNetlist() {
    const editor = document.getElementById("netlist-editor");
    const gutter = document.getElementById("netlist-gutter");
    if (!editor) return;

    editor.value = JSON.stringify(SAMPLE_NETLIST, null, 2);
    if (gutter) {
        const lines = editor.value.split("\n").length;
        let numbers = "";
        for (let i = 1; i <= lines; i++) numbers += i + "\n";
        gutter.textContent = numbers;
    }
}

function initSampleButtons() {
    const btnPython = document.getElementById("btn-sample-py");
    const btnC = document.getElementById("btn-sample-c");
    const btnPragmatic = document.getElementById("btn-sample-pragmatic");
    const btnNetlist = document.getElementById("btn-sample-netlist");

    if (btnPython) btnPython.addEventListener("click", () => loadSampleCode("python"));
    if (btnC) btnC.addEventListener("click", () => loadSampleCode("c"));
    if (btnPragmatic) btnPragmatic.addEventListener("click", () => loadSampleCode("pragmatic"));
    if (btnNetlist) btnNetlist.addEventListener("click", () => loadSampleNetlist());

    const btnAnalyzeCode = document.getElementById("btn-analyze-code");
    if (btnAnalyzeCode) btnAnalyzeCode.addEventListener("click", runCodeAnalysis);

    const btnTracerBullet = document.getElementById("btn-tracer-bullet");
    if (btnTracerBullet) btnTracerBullet.addEventListener("click", runTracerBullet);

    const btnAnalyzeCircuit = document.getElementById("btn-analyze-circuit");
    if (btnAnalyzeCircuit) btnAnalyzeCircuit.addEventListener("click", runCircuitAnalysis);

    const btnExportSarif = document.getElementById("btn-export-sarif");
    if (btnExportSarif) btnExportSarif.addEventListener("click", exportSarif);
}

// ── API: Phase 1 Code Analysis ──────────────────────────────────────────────
async function runCodeAnalysis() {
    const editor = document.getElementById("code-editor");
    const btn = document.getElementById("btn-analyze-code");
    const resultsContainer = document.getElementById("code-results");

    if (!editor || !resultsContainer) return;
    const code = editor.value;
    if (!code.trim()) {
        alert("Please enter or load some source code to analyze.");
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Running Pragmatic Pipeline...';

    try {
        const response = await fetch("/api/analyze/code", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                source_code: code,
                filename: "demo.py",
                language: "python"
            })
        });

        const data = await response.json();
        renderCodeResults(data);
    } catch (err) {
        console.error("Analysis failed:", err);
        resultsContainer.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p>Analysis failed: ${err.message}</p></div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> Run Pragmatic Full Analysis';
    }
}

// ── API: Tracer Bullet Probe ────────────────────────────────────────────────
async function runTracerBullet() {
    const editor = document.getElementById("code-editor");
    const btn = document.getElementById("btn-tracer-bullet");

    if (!editor) return;
    const code = editor.value;
    if (!code.trim()) {
        alert("Please enter or load code before firing a tracer bullet.");
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Firing Bullet...';
    }

    try {
        const response = await fetch("/api/tracer-bullet", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ source_code: code })
        });
        const tracer = await response.json();
        renderTracerConsole(tracer);

        // Switch to Pragmatic tab so user sees the tracer bullet telemetry
        const tabPragmatic = document.querySelector('.tab-btn[data-tab="tab-pragmatic"]');
        if (tabPragmatic) {
            tabPragmatic.click();
            const consoleCard = document.getElementById("tracer-console-container");
            if (consoleCard) consoleCard.scrollIntoView({ behavior: "smooth" });
        }
    } catch (err) {
        alert("Tracer Bullet failed: " + err.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<span>🎯</span> Fire Tracer Bullet';
        }
    }
}

// ── API: Phase 2 Circuit Analysis ───────────────────────────────────────────
async function runCircuitAnalysis() {
    const editor = document.getElementById("netlist-editor");
    const btn = document.getElementById("btn-analyze-circuit");
    const resultsContainer = document.getElementById("circuit-results");

    if (!editor || !resultsContainer) return;

    let netlistObj;
    try {
        netlistObj = JSON.parse(editor.value);
    } catch (e) {
        alert("Invalid JSON format in Netlist editor: " + e.message);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing Netlist...';

    try {
        const response = await fetch("/api/analyze/circuit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ netlist: netlistObj })
        });

        const data = await response.json();
        renderCircuitResults(data);
    } catch (err) {
        console.error("Circuit analysis failed:", err);
        resultsContainer.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p>Circuit analysis failed: ${err.message}</p></div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> Run Full Phase 2 Analysis';
    }
}

// ── Render Phase 1 Diagnostics ──────────────────────────────────────────────
function renderCodeResults(data) {
    const resultsContainer = document.getElementById("code-results");
    const countTotal = document.getElementById("stat-code-total");
    const countCrit = document.getElementById("stat-code-crit");
    const countBw = document.getElementById("stat-code-bw");
    const countDbc = document.getElementById("stat-code-dbc");
    const statStatus = document.getElementById("stat-code-status");

    // Header badge
    const headerBwCount = document.getElementById("header-bw-count");
    const headerBwGrade = document.getElementById("header-bw-grade");
    const badgeBw = document.getElementById("badge-broken-windows");

    const highlights = data.highlights || [];
    const pragmatic = data.pragmatic_analysis || {};
    const brokenWindows = pragmatic.broken_windows || { total_score: 0, windows_count: 0, clean_code_rating: "A+" };
    const contractViolations = pragmatic.contract_violations || [];
    const refactoringAdvice = pragmatic.refactoring_advice || [];

    let crit = 0, warn = 0, info = 0;
    highlights.forEach(h => {
        const sev = (h.severity || "").toUpperCase();
        if (sev === "CRITICAL") crit++;
        else if (sev === "WARNING") warn++;
        else info++;
    });

    if (countTotal) countTotal.textContent = highlights.length;
    if (countCrit) countCrit.textContent = crit;
    if (countBw) countBw.textContent = `${brokenWindows.total_score}% (${brokenWindows.clean_code_rating})`;
    if (countDbc) countDbc.textContent = `${contractViolations.length} Violations`;

    if (statStatus) {
        statStatus.textContent = crit > 0 ? "ACTION REQ" : (brokenWindows.total_score > 0 ? "DEBT DETECTED" : "PRISTINE");
        statStatus.style.color = crit > 0 ? "#dc2626" : (brokenWindows.total_score > 0 ? "#d97706" : "#16a34a");
    }

    // Update Header broken windows pill
    if (headerBwCount) headerBwCount.textContent = brokenWindows.windows_count;
    if (headerBwGrade) headerBwGrade.textContent = brokenWindows.clean_code_rating;
    if (badgeBw) {
        badgeBw.classList.remove("pristine", "critical");
        if (brokenWindows.windows_count === 0) {
            badgeBw.classList.add("pristine");
        } else if (brokenWindows.total_score > 40) {
            badgeBw.classList.add("critical");
        }
    }

    // Render Pragmatic Tab Sub-Panels
    renderBrokenWindowsScorecard(brokenWindows);
    renderDbCMatrix(contractViolations);
    if (pragmatic.tracer_bullet) {
        renderTracerConsole(pragmatic.tracer_bullet);
    }

    if (highlights.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <p><strong>Pristine Code Quality!</strong> Zero broken windows, clean contracts, and zero memory or taint faults.</p>
            </div>
        `;
        return;
    }

    let html = "";
    highlights.forEach((d, idx) => {
        const sevClass = (d.severity || "info").toLowerCase();
        const rTot = d.scores && d.scores.r_total !== undefined ? d.scores.r_total.toFixed(2) : "0.95";
        const ruleId = d.rule_id || "CODE-000";
        const line = d.code_span ? d.code_span.start_line : (d.causal_trace && d.causal_trace[0] ? d.causal_trace[0].line : "N/A");

        // Find contract violation if matching
        const matchingContract = contractViolations.find(c => c.line === line || (c.function_or_scope && c.function_or_scope.includes(ruleId)));
        const matchingAdvice = refactoringAdvice.find(a => a.rule_id === ruleId);

        html += `
            <div class="diag-card sev-${sevClass}">
                <div class="diag-header">
                    <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span class="rule-badge sev-${sevClass}">${ruleId}</span>
                        ${matchingContract ? `
                            <span class="dbc-badge" title="Design by Contract Fault: ${matchingContract.fault_party}">
                                📐 DbC ${matchingContract.contract_type}
                            </span>
                        ` : ''}
                        <span class="etc-badge" title="Pragmatic Tip 8: Good Design is Easier to Change (ETC)">
                            ETC Refactoring
                        </span>
                    </div>
                    <div class="diag-score">
                        Priority R_total: <span class="score-pill">${rTot}</span>
                    </div>
                </div>
                <div class="diag-message">${escapeHtml(d.message)}</div>
                <div class="diag-location">📍 File: ${d.code_span ? d.code_span.file : 'source.py'} | Line ${line}</div>
        `;

        // Formal Contract Clause
        if (matchingContract) {
            html += `
                <div style="background: #f5f3ff; border: 1px solid #c4b5fd; border-radius: 6px; padding: 7px 10px; margin-bottom: 8px; font-size: 11px; color: #5b21b6;">
                    <strong>Formal Contract Clause:</strong> <code>${escapeHtml(matchingContract.formal_clause)}</code>
                    <span style="margin-left: 8px; font-weight: 700; color: #7c3aed;">[Fault: ${matchingContract.fault_party}]</span>
                </div>
            `;
        }

        // Caret Overlay
        if (d.visual_overlay) {
            html += `<pre class="code-overlay-block">${escapeHtml(d.visual_overlay)}</pre>`;
        }

        // Causal Trace Badges
        if (d.causal_trace && d.causal_trace.length > 0) {
            html += `<div class="causal-trail">`;
            d.causal_trace.forEach((step, sIdx) => {
                html += `
                    <span class="causal-step">
                        <span class="step-num">${step.step_index || sIdx + 1}</span>
                        ${escapeHtml(step.label)}
                    </span>
                `;
                if (sIdx < d.causal_trace.length - 1) {
                    html += `<span class="trail-arrow">→</span>`;
                }
            });
            html += `</div>`;
        }

        // Auto Remediation Diff & ETC Refactoring Steps
        if (d.auto_remediation && d.auto_remediation.unified_diff) {
            const rawDiff = d.auto_remediation.unified_diff;
            html += `
                <div class="diff-box">
                    <div class="diff-header">
                        <span>⚡ AI-Synthesized Refactoring Diff (ETC Principle)</span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span>${d.auto_remediation.verification_status || 'SUGGESTED'}</span>
                            <button class="btn-verify-rule9" data-rule="${ruleId}" data-diff="${encodeURIComponent(rawDiff)}" onclick="verifyFixWithRule9(this)">
                                <span>✅</span> Verify Fix (Ruthless Test)
                            </button>
                        </div>
                    </div>
                    <pre style="margin: 0; padding: 6px 0;">`;
            rawDiff.split("\n").forEach(dl => {
                if (dl.startsWith("-")) {
                    html += `<div class="diff-line-del">${escapeHtml(dl)}</div>`;
                } else if (dl.startsWith("+")) {
                    html += `<div class="diff-line-add">${escapeHtml(dl)}</div>`;
                } else {
                    html += `<div style="padding: 2px 12px; color: #475569;">${escapeHtml(dl)}</div>`;
                }
            });
            html += `</pre>
                <div class="verify-output-container"></div>
            </div>`;
        }

        // Pragmatic Refactoring Guidance
        if (matchingAdvice) {
            html += `
                <div class="refactor-steps-box">
                    <strong style="color: #1558C9;">💡 Pragmatic Refactoring Roadmap (Tip 47: Refactor Early &amp; Often):</strong>
                    <div class="refactor-step">${escapeHtml(matchingAdvice.step_1)}</div>
                    <div class="refactor-step">${escapeHtml(matchingAdvice.step_2)}</div>
                    <div class="refactor-step">${escapeHtml(matchingAdvice.step_3)}</div>
                </div>
            `;
        }

        html += `</div>`;
    });

    resultsContainer.innerHTML = html;
}

// ── Render Phase 2 Circuit Diagnostics ──────────────────────────────────────
function renderCircuitResults(data) {
    const resultsContainer = document.getElementById("circuit-results");
    const countTotal = document.getElementById("stat-circ-total");
    const countCrit = document.getElementById("stat-circ-crit");
    const countViolet = document.getElementById("stat-circ-violet");
    const statStatus = document.getElementById("stat-circ-status");

    const highlights = data.highlights || [];

    let crit = 0, warn = 0, violet = 0;
    highlights.forEach(h => {
        const sev = (h.severity || "").toUpperCase();
        if (sev === "CRITICAL") crit++;
        else if (sev === "WARNING") warn++;
        else if (sev === "VIOLET_NET") violet++;
    });

    if (countTotal) countTotal.textContent = highlights.length;
    if (countCrit) countCrit.textContent = crit;
    if (countViolet) countViolet.textContent = violet;
    if (statStatus) {
        statStatus.textContent = crit > 0 ? "ACTION REQ" : (violet > 0 || warn > 0 ? "REVIEW" : "CLEAN");
        statStatus.style.color = crit > 0 ? "#dc2626" : (violet > 0 ? "#7c3aed" : (warn > 0 ? "#d97706" : "#16a34a"));
    }

    if (highlights.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <p><strong>Netlist Verified!</strong> No timing violations, floating nets, CDC issues, or power drops.</p>
            </div>
        `;
        return;
    }

    let html = "";
    highlights.forEach(d => {
        const sevClass = (d.severity || "info").toLowerCase();
        const ruleId = d.rule_id || "CIRC-000";
        const probe = d.circuit_probe || {};
        const cone = (probe.gate_instances && probe.gate_instances.length > 0) ? probe.gate_instances.join(", ") : "Logic Path";
        const vcdStr = probe.vcd_window_ps ? `[${probe.vcd_window_ps[0]} ps -> ${probe.vcd_window_ps[1]} ps]` : "[18420 ps -> 18980 ps]";
        const bboxStr = probe.gdsii_bbox ? probe.gdsii_bbox.join(", ") : "M3: (142.4, 88.0, 219.6, 104.2) µm";

        html += `
            <div class="diag-card sev-${sevClass}">
                <div class="diag-header">
                    <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span class="rule-badge sev-${sevClass}">${ruleId}</span>
                        <span class="dbc-badge">Hardware Contract</span>
                    </div>
                    <div class="diag-score">
                        ${d.slack_ns !== undefined ? `Slack: <span class="score-pill" style="color: ${d.slack_ns < 0 ? '#dc2626' : '#16a34a'}">${d.slack_ns.toFixed(3)} ns</span> | ` : ''}
                        Priority: <span class="score-pill">${(d.scores && d.scores.r_total ? d.scores.r_total.toFixed(2) : '0.90')}</span>
                    </div>
                </div>
                <div class="diag-message">${escapeHtml(d.message)}</div>

                <!-- 4-View Cross-Probe Card -->
                <div class="probe-card">
                    <div class="probe-header">
                        <span>Synchronized 4-View Cross-Probe</span>
                        <span style="color: #64748b; font-family: monospace;">TELEMETRY ACTIVE</span>
                    </div>
                    <div class="probe-grid">
                        <div style="background: #f8fafc; padding: 8px 10px; border-radius: 5px; border-left: 3px solid #1558C9; border: 1px solid #e2e8f0; border-left-width: 3px;">
                            <strong style="color: #1558C9;">View 1: RTL Source</strong>
                            <div style="font-family: monospace; color: #0f172a; margin-top: 2px;">${probe.module || 'core_alu'}.sv:84</div>
                        </div>
                        <div style="background: #f8fafc; padding: 8px 10px; border-radius: 5px; border-left: 3px solid #7c3aed; border: 1px solid #e2e8f0; border-left-width: 3px;">
                            <strong style="color: #7c3aed;">View 2: Schematic Cone</strong>
                            <div style="font-family: monospace; color: #0f172a; margin-top: 2px;">${escapeHtml(cone)}</div>
                        </div>
                        <div style="background: #f8fafc; padding: 8px 10px; border-radius: 5px; border-left: 3px solid #16a34a; border: 1px solid #e2e8f0; border-left-width: 3px;">
                            <strong style="color: #15803d;">View 3: Waveform Cursor</strong>
                            <div style="font-family: monospace; color: #0f172a; margin-top: 2px;">${vcdStr}</div>
                        </div>
                        <div style="background: #f8fafc; padding: 8px 10px; border-radius: 5px; border-left: 3px solid #1558C9; border: 1px solid #e2e8f0; border-left-width: 3px;">
                            <strong style="color: #1558C9;">View 4: GDSII Coordinates</strong>
                            <div style="font-family: monospace; color: #0f172a; margin-top: 2px;">${escapeHtml(bboxStr)}</div>
                        </div>
                    </div>
                </div>

                <!-- Remediation -->
                ${d.auto_remediation ? `
                    <div style="font-size: 12px; background: #ecfccb; border: 1px solid #84cc16; border-radius: 6px; padding: 8px 12px; color: #365314; margin-top: 8px;">
                        <strong style="color: #1a2e05;">Recommended Hardware ECO:</strong> ${escapeHtml(d.auto_remediation.summary || d.auto_remediation.action)}
                    </div>
                ` : ''}
            </div>
        `;
    });

    resultsContainer.innerHTML = html;
}

// ── Render Broken Windows Scorecard ─────────────────────────────────────────
function renderBrokenWindowsScorecard(bw) {
    if (!bw) return;

    const scoreNum = document.getElementById("bw-score-num");
    const statusPill = document.getElementById("bw-status-pill");
    const adviceText = document.getElementById("bw-advice-text");
    const container = document.getElementById("bw-items-container");

    if (scoreNum) scoreNum.textContent = bw.total_score || 0;
    if (adviceText) adviceText.textContent = bw.advice || "";

    if (statusPill) {
        statusPill.textContent = `Clean Code: ${bw.clean_code_rating || "A+"}`;
        if (bw.total_score === 0) {
            statusPill.style.background = "#ecfccb";
            statusPill.style.color = "#365314";
            statusPill.style.borderColor = "#84cc16";
        } else if (bw.total_score <= 30) {
            statusPill.style.background = "#fffbeb";
            statusPill.style.color = "#92400e";
            statusPill.style.borderColor = "#fcd34d";
        } else {
            statusPill.style.background = "#fef2f2";
            statusPill.style.color = "#991b1b";
            statusPill.style.borderColor = "#fca5a5";
        }
    }

    if (!container) return;

    const windows = bw.windows || [];
    if (windows.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding: 24px 10px;">
                <div class="empty-icon">🧼</div>
                <p><strong>Zero Broken Windows Detected!</strong><br>Codebase adheres to Clean Coding and Orthogonality standards.</p>
            </div>
        `;
        return;
    }

    let html = "";
    windows.forEach(w => {
        html += `
            <div class="bw-item">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: #92400e; font-size: 13px;">🪟 ${escapeHtml(w.category)}</strong>
                    <span class="score-pill" style="color: #b45309;">Line ${w.line} | Entropy +${w.entropy_weight}</span>
                </div>
                <div style="color: #334155; font-size: 12px;">${escapeHtml(w.description)}</div>
                <div style="font-size: 11px; color: #1558C9; font-weight: 600;">${escapeHtml(w.clean_code_tip)}</div>
                <div style="font-size: 11px; background: #f8fafc; padding: 4px 8px; border-radius: 4px; color: #475569;">
                    <strong>Remedy:</strong> ${escapeHtml(w.remediation_hint)}
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

// ── Render Design by Contract Matrix ────────────────────────────────────────
function renderDbCMatrix(violations) {
    const container = document.getElementById("dbc-matrix-container");
    if (!container) return;

    if (!violations || violations.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding: 24px 10px;">
                <div class="empty-icon">📐</div>
                <p><strong>Contracts Fully Satisfied</strong><br>Preconditions, postconditions, and class invariants are upheld.</p>
            </div>
        `;
        return;
    }

    let html = "";
    violations.forEach(v => {
        html += `
            <div class="dbc-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="dbc-badge">${v.contract_type}</span>
                    <span style="font-size: 11px; color: #5b21b6; font-weight: 700;">Fault: ${v.fault_party}</span>
                </div>
                <div style="font-size: 12px; font-weight: 700; color: #0f172a; margin-top: 2px;">
                    ${escapeHtml(v.function_or_scope)} (Line ${v.line})
                </div>
                <div style="font-family: monospace; font-size: 11px; background: #f5f3ff; padding: 4px 8px; border-radius: 4px; color: #4c1d95;">
                    ${escapeHtml(v.formal_clause)}
                </div>
                <div style="font-size: 11px; color: #dc2626;">
                    <strong>Breach:</strong> ${escapeHtml(v.breached_expression)}
                </div>
                <div style="font-size: 11px; color: #15803d; font-weight: 600;">
                    <strong>Contract Obligation:</strong> ${escapeHtml(v.remedy)}
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

// ── Render Tracer Bullet Console ────────────────────────────────────────────
function renderTracerConsole(tracer) {
    const grid = document.getElementById("tracer-stages-grid");
    if (!grid || !tracer) return;

    const stages = tracer.stages || [];
    let html = "";
    stages.forEach(s => {
        const isPass = s.status === "PASS";
        html += `
            <div class="tracer-stage-item ${isPass ? 'pass' : 'fail'}">
                <div class="tracer-stage-header">
                    <span class="tracer-dot"></span>
                    <strong>${escapeHtml(s.name)}</strong>
                </div>
                <div style="font-size: 11px; color: #475569; line-height: 1.4;">
                    ${escapeHtml(s.output_summary)}
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: auto; padding-top: 6px; border-top: 1px dashed rgba(0,0,0,0.1);">
                    <span class="tracer-status">${s.status}</span>
                    <span style="font-family: monospace; font-size: 10px; color: var(--text-dim);">${s.duration_ms} ms</span>
                </div>
            </div>
        `;
    });
    grid.innerHTML = html;
}

// ── Load Canonical Pragmatic Principles & Tips ──────────────────────────────
async function loadPragmaticPrinciples() {
    const grid = document.getElementById("pragmatic-pillars-grid");
    if (!grid) return;

    try {
        const res = await fetch("/api/pragmatic-principles");
        const data = await res.json();
        const tips = data.tips || [];

        let html = "";
        tips.forEach(t => {
            html += `
                <div class="pragmatic-pillar-card">
                    <div class="pillar-header">
                        <span class="pillar-tip-num">TIP ${t.number}</span>
                        <span style="font-size: 11px; color: var(--color-cobalt); font-weight: 700; text-transform: uppercase;">
                            ${escapeHtml(t.pillar.replace('_', ' '))}
                        </span>
                    </div>
                    <div class="pillar-title">${escapeHtml(t.title)}</div>
                    <div class="pillar-quote">"${escapeHtml(t.quote)}"</div>
                    <div class="pillar-action">
                        <strong style="color: #0f172a;">Engineering Practice:</strong> ${escapeHtml(t.actionable_rule)}
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: auto; font-size: 11px; color: var(--text-dim);">
                        <span>Telemetry Metric:</span>
                        <code style="color: #1558C9; font-weight: 600;">${escapeHtml(t.telemetry_metric)}</code>
                    </div>
                </div>
            `;
        });
        grid.innerHTML = html;
    } catch (err) {
        console.error("Failed to load pragmatic principles:", err);
    }
}

// ── Export SARIF v2.1.0 ─────────────────────────────────────────────────────
async function exportSarif() {
    const editor = document.getElementById("code-editor");
    if (!editor) return;

    try {
        const res = await fetch("/api/analyze/code", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                source_code: editor.value,
                filename: "app.py",
                language: "python"
            })
        });

        const data = await res.json();
        const sarifRes = await fetch("/api/export/sarif", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const sarifJson = await sarifRes.json();
        const blob = new Blob([JSON.stringify(sarifJson, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pragmatic-audit-${Date.now()}.sarif`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        alert("SARIF export failed: " + e.message);
    }
}

// ── Rule Catalog Toggle & Loader ────────────────────────────────────────────
function initCatalogToggle() {
    const header = document.querySelector(".catalog-header");
    const body = document.getElementById("catalog-body");
    if (header && body) {
        header.addEventListener("click", () => {
            const isHidden = body.style.display === "none";
            body.style.display = isHidden ? "block" : "none";
            const icon = header.querySelector(".toggle-icon");
            if (icon) icon.textContent = isHidden ? "▲" : "▼";
        });
    }
}

async function loadCatalogRules() {
    try {
        const res = await fetch("/api/rules");
        const data = await res.json();
        const rules = Array.isArray(data) ? data : (data.rules || []);
        const tbody = document.getElementById("catalog-tbody");
        if (!tbody) return;

        let rows = "";
        rules.forEach(r => {
            const sevClass = (r.severity || "").toLowerCase();
            const agansBadge = r.agans_rule ? `<span class="agans-badge">📖 ${escapeHtml(r.agans_rule)}</span>` : '<span style="color: var(--text-dim); font-size: 11px;">Standard Rule</span>';
            const agansSummary = r.agans_summary ? `<div style="font-size: 11px; color: #475569; margin-top: 4px;">${escapeHtml(r.agans_summary)}</div>` : '';
            rows += `
                <tr>
                    <td><span class="rule-badge sev-${sevClass}">${r.rule_id}</span></td>
                    <td style="font-size: 12px; color: #475569; font-weight: 600;">${r.phase}</td>
                    <td><strong style="color: #0f172a; font-size: 13px;">${escapeHtml(r.category)}</strong></td>
                    <td style="font-size: 12px; color: #334155; font-family: monospace;">${escapeHtml(r.detection_predicate)}</td>
                    <td style="font-size: 12px; color: #15803d; font-weight: 600;">${escapeHtml(r.fix_strategy)}</td>
                    <td>${agansBadge}${agansSummary}</td>
                </tr>
            `;
        });
        tbody.innerHTML = rows;
    } catch (e) {
        console.error("Failed to load catalog rules:", e);
    }
}

// ── Rule 9: Live Fix Verification ("Ruthless Testing") ──────────────────────
async function verifyFixWithRule9(btn) {
    const ruleId = btn.getAttribute("data-rule");
    const diff = decodeURIComponent(btn.getAttribute("data-diff"));
    const container = btn.closest(".diff-box").querySelector(".verify-output-container");
    const editor = document.getElementById("code-editor");
    if (!editor || !container) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Running Ruthless Tests...';

    try {
        const response = await fetch("/api/verify-fix", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                source_code: editor.value,
                rule_id: ruleId,
                unified_diff: diff,
                language: "python"
            })
        });

        const res = await response.json();
        if (res.verified) {
            container.innerHTML = `
                <div class="verify-status-banner success">
                    <span>✅</span>
                    <div>
                        <strong>Pragmatic Ruthless Testing Passed: "Coding Ain't Done 'Til All Tests Run"</strong><br>
                        ${escapeHtml(res.message)}
                        <div style="margin-top: 4px; font-size: 11px; color: #166534;">
                            Target Rule: <code>${escapeHtml(res.target_rule_id)}</code> | Regressions: <strong>0</strong> | AST: <strong>Valid</strong>
                        </div>
                    </div>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="verify-status-banner error">
                    <span>⚠️</span>
                    <div>
                        <strong>Ruthless Test Warning: Fix Incomplete or Regressed</strong><br>
                        ${escapeHtml(res.message)}
                    </div>
                </div>
            `;
        }
    } catch (err) {
        container.innerHTML = `
            <div class="verify-status-banner error">
                <span>⚠️</span>
                <div>Verification error: ${escapeHtml(err.message)}</div>
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>✅</span> Verify Fix (Ruthless Test)';
    }
}

// ── Baseline Sanity Checks ("Check the Plug") ───────────────────────────────
function initCheckPlugButtons() {
    const btnCode = document.getElementById("btn-check-plug-code");
    const btnCirc = document.getElementById("btn-check-plug-circuit");

    if (btnCode) {
        btnCode.addEventListener("click", async () => {
            const editor = document.getElementById("code-editor");
            if (!editor) return;
            btnCode.disabled = true;
            btnCode.innerHTML = '<span class="spinner"></span> Checking Plug...';
            try {
                const res = await fetch("/api/check-plug", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ source_code: editor.value })
                });
                const data = await res.json();
                if (data.status === "PASS") {
                    alert("🔌 Pre-Flight Sanity Passed!\n\nAll basic prerequisites met:\n✓ Non-empty source buffer\n✓ Valid syntax tree\n✓ No literal zero denominators\n✓ Base contracts intact.");
                } else {
                    const issuesList = data.issues.map((iss, i) => `${i + 1}. [Line ${iss.line || 1}] ${iss.message}`).join("\n");
                    alert(`🔌 Pre-Flight Sanity Found ${data.sanity_issues_count} Basic Issue(s):\n\n${issuesList}\n\nFix these fundamental issues before running heavy symbolic analysis!`);
                }
            } catch (err) {
                alert("Check the Plug failed: " + err.message);
            } finally {
                btnCode.disabled = false;
                btnCode.innerHTML = '<span>🔌</span> Check the Plug';
            }
        });
    }

    if (btnCirc) {
        btnCirc.addEventListener("click", async () => {
            const editor = document.getElementById("netlist-editor");
            if (!editor) return;
            btnCirc.disabled = true;
            btnCirc.innerHTML = '<span class="spinner"></span> Checking Plug...';
            try {
                let netlistObj = {};
                try {
                    netlistObj = JSON.parse(editor.value);
                } catch (e) {
                    alert("🔌 Pre-Flight Sanity Failed: Netlist JSON syntax is invalid: " + e.message);
                    return;
                }
                const res = await fetch("/api/check-plug", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ netlist: netlistObj })
                });
                const data = await res.json();
                if (data.status === "PASS") {
                    alert("🔌 Pre-Flight Sanity Passed!\n\nAll basic circuit prerequisites met:\n✓ Non-empty netlist structure\n✓ All gate inputs connected to valid drivers or supply rails\n✓ Power ground connectivity intact.");
                } else {
                    const issuesList = data.issues.map((iss, i) => `${i + 1}. ${iss.message}`).join("\n");
                    alert(`🔌 Pre-Flight Sanity Found ${data.sanity_issues_count} Basic Issue(s):\n\n${issuesList}`);
                }
            } catch (err) {
                alert("Check the Plug failed: " + err.message);
            } finally {
                btnCirc.disabled = false;
                btnCirc.innerHTML = '<span>🔌</span> Check the Plug';
            }
        });
    }
}

// ── David J. Agans' 9 Indispensable Rules Protocol Implementation ───────────
function initAgansProtocol() {
    const btn = document.getElementById("btn-header-agans");
    if (btn) {
        btn.addEventListener("click", () => {
            const agansTab = document.querySelector('.tab-btn[data-tab="tab-agans"]');
            if (agansTab) {
                agansTab.click();
                const agansSection = document.getElementById("tab-agans");
                if (agansSection) {
                    agansSection.scrollIntoView({ behavior: "smooth" });
                }
            }
        });
    }
    loadAgansRules();
}

async function loadAgansRules() {
    const grid = document.getElementById("agans-rules-grid");
    if (!grid) return;

    try {
        const res = await fetch("/api/agans-rules");
        const data = await res.json();
        const rules = data.rules || [];

        let html = "";
        rules.forEach(r => {
            html += `
                <div class="agans-card">
                    <div class="agans-card-header">
                        <span class="agans-rule-number">RULE ${r.rule_number}</span>
                        <span style="font-size: 11px; color: var(--color-cobalt); font-weight: 700; font-family: monospace;">${escapeHtml(r.telemetry_hook)}</span>
                    </div>
                    <div class="agans-card-title">${escapeHtml(r.title)}</div>
                    <div class="agans-mantra">"${escapeHtml(r.mantra)}"</div>
                    <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">${escapeHtml(r.summary)}</p>
                    
                    <div class="agans-section-block">
                        <div class="agans-section-label code-label">
                            <span>💻</span> Software Code Implementation:
                        </div>
                        <div class="agans-section-text">${escapeHtml(r.software_application)}</div>
                    </div>

                    <div class="agans-section-block">
                        <div class="agans-section-label circuit-label">
                            <span>🔌</span> Hardware Circuit Implementation:
                        </div>
                        <div class="agans-section-text">${escapeHtml(r.circuit_application)}</div>
                    </div>
                </div>
            `;
        });
        grid.innerHTML = html;
    } catch (err) {
        console.error("Failed to load Agans rules:", err);
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

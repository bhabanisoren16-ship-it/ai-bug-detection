/**
 * AI Bug Detection & Highlighting System — Client Application
 * Dual-Phase Automated Defect Localization & Multi-Layer Visual Highlighting
 */

document.addEventListener("DOMContentLoaded", () => {
    initThemeSelector();
    initTabs();
    initLineNumbers();
    initSampleButtons();
    initCatalogToggle();
    loadCatalogRules();

    // Default sample load: Python defect sample
    loadSampleCode("python");
    loadSampleNetlist();
});

// ── Theme Selector ──────────────────────────────────────────────────────────
function initThemeSelector() {
    const select = document.getElementById("theme-select");
    if (!select) return;

    const savedTheme = localStorage.getItem("bug_detector_theme") || "theme-cyberpunk";
    applyTheme(savedTheme);
    select.value = savedTheme;

    select.addEventListener("change", (e) => {
        const theme = e.target.value;
        applyTheme(theme);
        localStorage.setItem("bug_detector_theme", theme);
    });
}

function applyTheme(themeName) {
    document.body.classList.remove("theme-cyberpunk", "theme-light");
    if (themeName && themeName === "theme-light") {
        document.body.classList.add("theme-light");
    } else {
        document.body.classList.add("theme-cyberpunk");
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
    python: `import os

def process_packet(data):
    # Allocate packet buffer
    buf = allocate_buffer(1024)
    
    # Unsanitized user input -> SQL Query (Taint Vulnerability)
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
    
    // Division by zero
    int rate = 100 / count;
    
    if (sock < 0) {
        free(session);
    }
    
    // Use-After-Free: session dereferenced after free
    session[0] = 'A';
    
    // Buffer overflow: off-by-one boundary
    int arr[10];
    for (int i = 0; i <= 10; i++) {
        arr[i] = i * 2;
    }
}
`
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

    editor.value = SAMPLES[type] || SAMPLES.python;
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
    const btnNetlist = document.getElementById("btn-sample-netlist");

    if (btnPython) btnPython.addEventListener("click", () => loadSampleCode("python"));
    if (btnC) btnC.addEventListener("click", () => loadSampleCode("c"));
    if (btnNetlist) btnNetlist.addEventListener("click", () => loadSampleNetlist());

    const btnAnalyzeCode = document.getElementById("btn-analyze-code");
    if (btnAnalyzeCode) btnAnalyzeCode.addEventListener("click", runCodeAnalysis);

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

    if (!editor || !btn) return;
    const sourceCode = editor.value;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Detecting Bugs...';
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon"><span class="spinner"></span></div>
            <p><strong>Running Dual-Phase Detection Engine...</strong><br>Parsing AST, analyzing memory lifecycles, and evaluating taint paths.</p>
        </div>
    `;

    try {
        const payload = {
            source_code: sourceCode,
            filename: "source.py",
            language: sourceCode.includes("#include") ? "c" : "python"
        };

        const res = await fetch("/api/analyze/code", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
        const data = await res.json();
        renderCodeResults(data, sourceCode);
    } catch (err) {
        resultsContainer.innerHTML = `
            <div class="empty-state" style="border-color: var(--color-critical);">
                <div class="empty-icon">⚠️</div>
                <p><strong>Analysis Error:</strong><br>${escapeHtml(err.message)}</p>
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> Run Bug Detection';
    }
}

// ── Render Phase 1 Code Results ─────────────────────────────────────────────
function renderCodeResults(data, sourceCode) {
    const resultsContainer = document.getElementById("code-results");
    const countTotal = document.getElementById("stat-code-total");
    const countCrit = document.getElementById("stat-code-crit");
    const countWarn = document.getElementById("stat-code-warn");
    const statStatus = document.getElementById("stat-code-status");

    const highlights = data.highlights || [];
    let crit = 0, warn = 0;

    highlights.forEach(h => {
        const sev = (h.severity || "").toUpperCase();
        if (sev === "CRITICAL" || sev === "ERROR") crit++;
        else warn++;
    });

    if (countTotal) countTotal.textContent = highlights.length;
    if (countCrit) countCrit.textContent = crit;
    if (countWarn) countWarn.textContent = warn;
    if (statStatus) {
        statStatus.textContent = crit > 0 ? "ACTION REQ" : (highlights.length > 0 ? "REVIEW" : "CLEAN");
        statStatus.style.color = crit > 0 ? "#dc2626" : (highlights.length > 0 ? "#d97706" : "#16a34a");
    }

    if (highlights.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <p><strong>Zero Bugs Detected!</strong><br>Codebase passes all AST, taint, and memory safety checks cleanly.</p>
            </div>
        `;
        return;
    }

    const lines = sourceCode.split("\n");
    let html = "";

    highlights.forEach((h, idx) => {
        const lineNum = h.line || 1;
        const codeLine = lines[lineNum - 1] || "";
        const sevClass = (h.severity || "warning").toLowerCase();

        // Causal trail HTML
        let causalHtml = "";
        if (h.causal_trail && h.causal_trail.length > 0) {
            causalHtml = `
                <div class="causal-trail">
                    ${h.causal_trail.map(c => `<span class="causal-step">Step ${c.step}: ${escapeHtml(c.desc)}</span>`).join(" ➔ ")}
                </div>
            `;
        }

        // Patch Diff Box
        let patchHtml = "";
        if (h.patch_diff) {
            const diffLines = h.patch_diff.split("\n").map(l => {
                if (l.startsWith("+")) return `<div class="diff-add">${escapeHtml(l)}</div>`;
                if (l.startsWith("-")) return `<div class="diff-del">${escapeHtml(l)}</div>`;
                return `<div>${escapeHtml(l)}</div>`;
            }).join("");

            patchHtml = `
                <div class="diff-box">
                    <div class="diff-header">
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <span>🛠️</span>
                            <strong>Automated Fix Patch</strong>
                        </div>
                        <button class="btn btn-secondary btn-sm btn-verify-fix"
                                data-diagnostic-id="${h.diagnostic_id || idx}"
                                data-rule-id="${h.rule_id}"
                                data-patch="${encodeURIComponent(h.patch_diff)}">
                            <span>⚡</span> Apply Fix &amp; Verify
                        </button>
                    </div>
                    <div class="diff-body">${diffLines}</div>
                    <div id="verify-status-${h.diagnostic_id || idx}"></div>
                </div>
            `;
        }

        html += `
            <div class="diag-card ${sevClass}" id="diag-card-${h.diagnostic_id || idx}">
                <div class="diag-header">
                    <div class="diag-title">
                        <span class="badge ${sevClass}">${escapeHtml(h.severity)}</span>
                        <strong>${escapeHtml(h.category || "Bug")}</strong>
                        <span style="font-family: monospace; font-size: 11px; color: var(--text-dim);">${escapeHtml(h.rule_id)}</span>
                    </div>
                    <span class="diag-location">Line ${lineNum}:${h.column || 1}</span>
                </div>

                <div class="diag-message">${escapeHtml(h.message)}</div>
                ${causalHtml}

                <div class="code-overlay-block">
                    <span class="line-badge">Line ${lineNum}</span>
                    <code>${escapeHtml(codeLine.trim())}</code>
                </div>

                ${patchHtml}
            </div>
        `;
    });

    resultsContainer.innerHTML = html;

    // Attach patch fix handlers
    document.querySelectorAll(".btn-verify-fix").forEach(btn => {
        btn.addEventListener("click", () => verifyFix(btn));
    });
}

// ── API: Phase 2 Circuit Analysis ───────────────────────────────────────────
async function runCircuitAnalysis() {
    const editor = document.getElementById("netlist-editor");
    const btn = document.getElementById("btn-analyze-circuit");
    const resultsContainer = document.getElementById("circuit-results");

    if (!editor || !btn) return;

    let netlist;
    try {
        netlist = JSON.parse(editor.value);
    } catch (e) {
        alert("Invalid JSON format in Netlist Editor: " + e.message);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Verifying Circuit...';
    resultsContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon"><span class="spinner"></span></div>
            <p><strong>Running Phase 2 Engine...</strong><br>Checking static timing slack, CDC metastability, and floating pins.</p>
        </div>
    `;

    try {
        const res = await fetch("/api/analyze/circuit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ netlist: netlist })
        });

        if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
        const data = await res.json();
        renderCircuitResults(data);
    } catch (err) {
        resultsContainer.innerHTML = `
            <div class="empty-state" style="border-color: var(--color-critical);">
                <div class="empty-icon">⚠️</div>
                <p><strong>Circuit Verification Error:</strong><br>${escapeHtml(err.message)}</p>
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> Verify Circuit Netlist';
    }
}

// ── Render Phase 2 Circuit Results ──────────────────────────────────────────
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
                <p><strong>Netlist Verified!</strong><br>No timing violations, floating nets, CDC issues, or power drops.</p>
            </div>
        `;
        return;
    }

    let html = "";
    highlights.forEach(h => {
        const sevClass = (h.severity || "warning").toLowerCase();
        const views = h.cross_probe_views || {};

        html += `
            <div class="diag-card ${sevClass}">
                <div class="diag-header">
                    <div class="diag-title">
                        <span class="badge ${sevClass}">${escapeHtml(h.severity)}</span>
                        <strong>${escapeHtml(h.category || "Circuit Defect")}</strong>
                        <span style="font-family: monospace; font-size: 11px; color: var(--text-dim);">${escapeHtml(h.rule_id)}</span>
                    </div>
                    <span class="diag-location">Net: ${escapeHtml(h.net || "N/A")}</span>
                </div>

                <div class="diag-message">${escapeHtml(h.message)}</div>

                <!-- 4-View Synchronized Probe -->
                <div class="probe-card">
                    <div style="font-size: 11px; font-weight: 700; color: #475569; margin-bottom: 8px;">
                        🔬 4-View Cross-Probe Coordinates:
                    </div>
                    <div class="probe-grid">
                        <div class="probe-item">
                            <span class="probe-label rtl">RTL Source Span</span>
                            <span class="probe-value">${escapeHtml(views.rtl_span || "N/A")}</span>
                        </div>
                        <div class="probe-item">
                            <span class="probe-label schematic">Schematic Net</span>
                            <span class="probe-value">${escapeHtml(views.schematic_net || "N/A")}</span>
                        </div>
                        <div class="probe-item">
                            <span class="probe-label vcd">VCD Waveform Window</span>
                            <span class="probe-value">${escapeHtml(views.vcd_cursor_window || "N/A")}</span>
                        </div>
                        <div class="probe-item">
                            <span class="probe-label gdsii">GDSII Layer &amp; Box</span>
                            <span class="probe-value">${escapeHtml(views.gdsii_box ? JSON.stringify(views.gdsii_box) : "N/A")}</span>
                        </div>
                    </div>

                    ${h.remediation_advice ? `
                        <div style="margin-top: 10px; padding: 8px 12px; background: #ecfccb; border: 1px solid #84cc16; border-radius: 6px; font-size: 11px; color: #1a2e05;">
                            <strong>Remediation:</strong> ${escapeHtml(h.remediation_advice)}
                        </div>
                    ` : ""}
                </div>
            </div>
        `;
    });

    resultsContainer.innerHTML = html;
}

// ── Rule Catalog Table ──────────────────────────────────────────────────────
function initCatalogToggle() {
    const section = document.querySelector(".catalog-section");
    const header = document.querySelector(".catalog-header");
    const icon = document.querySelector(".toggle-icon");
    if (!section || !header) return;

    header.addEventListener("click", () => {
        section.classList.toggle("collapsed");
        if (icon) {
            icon.textContent = section.classList.contains("collapsed") ? "▼" : "▲";
        }
    });
}

async function loadCatalogRules() {
    const tbody = document.getElementById("catalog-tbody");
    if (!tbody) return;

    try {
        const res = await fetch("/api/rules");
        const data = await res.json();
        const rules = data.rules || [];

        let html = "";
        rules.forEach(r => {
            const ruleId = r.rule_id || "";
            const phase = r.phase || "";
            const category = r.category || r.bug_category || "";
            const predicate = r.detection_predicate || r.formal_detection_predicate || "";
            const fix = r.fix_strategy || r.automated_fix_strategy || "";
            const phaseLabel = phase === "PHASE_1_CODE" ? "Phase 1: Code" : "Phase 2: Circuit";
            const phaseClass = phase === "PHASE_1_CODE" ? "info" : "purple";

            html += `
                <tr>
                    <td><code>${escapeHtml(ruleId)}</code></td>
                    <td><span class="badge ${phaseClass}">${escapeHtml(phaseLabel)}</span></td>
                    <td style="color: #00f0ff; font-weight: 700;">${escapeHtml(category)}</td>
                    <td style="font-family: var(--font-mono); font-size: 12px; color: #cbd5e1;">${escapeHtml(predicate)}</td>
                    <td style="font-size: 12px; color: #D4FF24;">${escapeHtml(fix)}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        console.error("Failed to load catalog rules:", err);
    }
}

// ── Automated Fix Verification ──────────────────────────────────────────────
async function verifyFix(btn) {
    const diagId = btn.getAttribute("data-diagnostic-id");
    const ruleId = btn.getAttribute("data-rule-id");
    const patchDiff = decodeURIComponent(btn.getAttribute("data-patch"));
    const statusBox = document.getElementById(`verify-status-${diagId}`);

    const editor = document.getElementById("code-editor");
    if (!editor) return;
    const currentCode = editor.value;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Verifying Fix...';

    try {
        const res = await fetch("/api/verify-fix", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                original_source: currentCode,
                patch_diff: patchDiff,
                target_rule_id: ruleId
            })
        });

        const data = await res.json();
        if (data.is_fixed) {
            if (statusBox) {
                statusBox.innerHTML = `
                    <div class="verify-status-banner pass" style="margin-top: 10px; padding: 10px 14px; background: #ecfccb; border: 1px solid #84cc16; border-radius: 6px; font-size: 12px; color: #1a2e05;">
                        <strong>✅ Bug Fix Verified Successfully!</strong><br>
                        Defect <code>${escapeHtml(ruleId)}</code> eliminated with clean test execution.
                    </div>
                `;
            }
            if (data.patched_source) {
                editor.value = data.patched_source;
                const gutter = document.getElementById("code-gutter");
                if (gutter) {
                    const lines = data.patched_source.split("\n").length;
                    let numbers = "";
                    for (let i = 1; i <= lines; i++) numbers += i + "\n";
                    gutter.textContent = numbers;
                }
            }
            btn.innerHTML = '<span>✅</span> Verified Clean';
            btn.classList.remove("btn-secondary");
            btn.classList.add("btn-primary");
        } else {
            if (statusBox) {
                statusBox.innerHTML = `
                    <div class="verify-status-banner fail" style="margin-top: 10px; padding: 10px 14px; background: #fef2f2; border: 1px solid #fca5a5; border-radius: 6px; font-size: 12px; color: #991b1b;">
                        <strong>❌ Verification Failed:</strong> ${escapeHtml(data.message || "Bug persists in AST.")}
                    </div>
                `;
            }
            btn.disabled = false;
            btn.innerHTML = '<span>⚡</span> Retry Fix';
        }
    } catch (err) {
        alert("Verification failed: " + err.message);
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> Apply Fix &amp; Verify';
    }
}

// ── Export SARIF v2.1.0 ─────────────────────────────────────────────────────
async function exportSarif() {
    const editor = document.getElementById("code-editor");
    if (!editor) return;

    try {
        const payload = {
            source_code: editor.value,
            filename: "source.py",
            language: editor.value.includes("#include") ? "c" : "python"
        };

        const res = await fetch("/api/export/sarif", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `bug-audit-${Date.now()}.sarif`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (err) {
        alert("Failed to export SARIF: " + err.message);
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

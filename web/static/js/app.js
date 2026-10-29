/**
 * AI Bug Detection & Highlighting System — Client Application
 * Handles code editing, line numbering, API communication, and multi-layer
 * visual diagnostics rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Ensure clean white theme is always active
    document.body.classList.remove("theme-slate", "theme-navy", "theme-black");
    localStorage.removeItem("bug_detector_theme");

    initTabs();
    initLineNumbers();
    initSampleButtons();
    initCatalogToggle();
    loadCatalogRules();
    initCheckPlugButtons();

    // Default sample load
    loadSampleCode("python");
    loadSampleNetlist();
});

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

function loadSampleCode(lang) {
    const editor = document.getElementById("code-editor");
    const gutter = document.getElementById("code-gutter");
    if (editor && SAMPLES[lang]) {
        editor.value = SAMPLES[lang];
        if (gutter) {
            const lines = editor.value.split("\n").length;
            let numbers = "";
            for (let i = 1; i <= lines; i++) numbers += i + "\n";
            gutter.textContent = numbers;
        }
    }
}

function loadSampleNetlist() {
    const editor = document.getElementById("netlist-editor");
    const gutter = document.getElementById("netlist-gutter");
    if (editor) {
        editor.value = JSON.stringify(SAMPLE_NETLIST, null, 2);
        if (gutter) {
            const lines = editor.value.split("\n").length;
            let numbers = "";
            for (let i = 1; i <= lines; i++) numbers += i + "\n";
            gutter.textContent = numbers;
        }
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

    if (!editor || !resultsContainer) return;
    const code = editor.value;
    if (!code.trim()) {
        alert("Please enter or load some source code to analyze.");
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing Code...';

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
        btn.innerHTML = '<span>⚡</span> Run Full Phase 1 Analysis';
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
        resultsContainer.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p>Analysis failed: ${err.message}</p></div>`;
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
    const countWarn = document.getElementById("stat-code-warn");
    const statStatus = document.getElementById("stat-code-status");

    const highlights = data.highlights || [];

    let crit = 0, warn = 0, info = 0;
    highlights.forEach(h => {
        const sev = (h.severity || "").toUpperCase();
        if (sev === "CRITICAL") crit++;
        else if (sev === "WARNING") warn++;
        else info++;
    });

    if (countTotal) countTotal.textContent = highlights.length;
    if (countCrit) countCrit.textContent = crit;
    if (countWarn) countWarn.textContent = warn;
    if (statStatus) {
        statStatus.textContent = crit > 0 ? "ACTION REQ" : (warn > 0 ? "REVIEW" : "CLEAN");
        statStatus.style.color = crit > 0 ? "#dc2626" : (warn > 0 ? "#d97706" : "#16a34a");
    }

    if (highlights.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <p><strong>Clean Code!</strong> No bugs, memory leaks, taint issues, or arithmetic faults detected.</p>
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

        html += `
            <div class="diag-card sev-${sevClass}">
                <div class="diag-header">
                    <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span class="rule-badge sev-${sevClass}">${ruleId}</span>
                        ${d.agans_protocol && d.agans_protocol.primary_info ? `
                            <span class="agans-badge" title="${escapeHtml(d.agans_protocol.rationale || '')}">
                                📖 ${escapeHtml(d.agans_protocol.primary_info.badge_label || d.agans_rule || 'Agans Rule')}
                            </span>
                        ` : ''}
                    </div>
                    <div class="diag-score">
                        Priority R_total: <span class="score-pill">${rTot}</span>
                    </div>
                </div>
                <div class="diag-message">${escapeHtml(d.message)}</div>
                <div class="diag-location">📍 File: ${d.code_span ? d.code_span.file : 'source.py'} | Line ${line}</div>
        `;

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

        // Auto Remediation Diff
        if (d.auto_remediation && d.auto_remediation.unified_diff) {
            const rawDiff = d.auto_remediation.unified_diff;
            html += `
                <div class="diff-box">
                    <div class="diff-header">
                        <span>⚡ AI-Synthesized Patch Preview</span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span>${d.auto_remediation.verification_status || 'SUGGESTED'}</span>
                            <button class="btn-verify-rule9" data-rule="${ruleId}" data-diff="${encodeURIComponent(rawDiff)}" onclick="verifyFixWithRule9(this)">
                                <span>✅</span> Verify Fix (Rule 9)
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

        html += `</div>`;
    });

    resultsContainer.innerHTML = html;
}

// ── Render Phase 2 Diagnostics ──────────────────────────────────────────────
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
        const rTot = d.scores && d.scores.r_total !== undefined ? d.scores.r_total.toFixed(2) : "0.96";
        const ruleId = d.rule_id || "CIRC-000";

        html += `
            <div class="diag-card sev-${sevClass}">
                <div class="diag-header">
                    <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span class="rule-badge sev-${sevClass}">${ruleId}</span>
                        ${d.agans_protocol && d.agans_protocol.primary_info ? `
                            <span class="agans-badge" title="${escapeHtml(d.agans_protocol.rationale || '')}">
                                📖 ${escapeHtml(d.agans_protocol.primary_info.badge_label || d.agans_rule || 'Agans Rule')}
                            </span>
                        ` : ''}
                    </div>
                    <div class="diag-score">
                        ${d.slack_ns !== undefined ? `Slack: <span class="score-pill" style="color: ${d.slack_ns < 0 ? '#dc2626' : '#16a34a'}">${d.slack_ns.toFixed(3)} ns</span> | ` : ''}
                        Priority: <span class="score-pill">${rTot}</span>
                    </div>
                </div>
                <div class="diag-message">${escapeHtml(d.message)}</div>
        `;

        // 4-View Cross-Probe Card
        const color = sevClass === "critical" ? "#dc2626" : (sevClass === "violet_net" ? "#7c3aed" : (sevClass === "warning" ? "#d97706" : "#1558C9"));
        const probe = d.circuit_probe || {};
        const cone = (probe.gate_instances && probe.gate_instances.length > 0) ? probe.gate_instances.join(", ") : (d.highlight_style && d.highlight_style.cone ? d.highlight_style.cone.join(", ") : "Logic Path");
        const vcdStr = probe.vcd_window_ps ? `[${probe.vcd_window_ps[0]} ps -> ${probe.vcd_window_ps[1]} ps]` : "[18420 ps -> 18980 ps]";
        const bboxStr = probe.gdsii_bbox ? probe.gdsii_bbox.join(", ") : "M3: (142.4, 88.0, 219.6, 104.2) µm";

        html += `
            <div style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; margin: 10px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.03);">
                <div style="font-size: 11px; font-weight: 700; color: #1558C9; text-transform: uppercase; margin-bottom: 8px; display: flex; justify-content: space-between;">
                    <span>Synchronized 4-View Cross-Probe</span>
                    <span style="color: #64748b; font-family: monospace;">TELEMETRY ACTIVE</span>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; font-size: 11px;">
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
        `;

        // Remediation
        if (d.auto_remediation && (d.auto_remediation.summary || d.auto_remediation.action)) {
            const actionText = d.auto_remediation.summary || d.auto_remediation.action;
            html += `
                <div style="font-size: 12px; background: #ecfccb; border: 1px solid #84cc16; border-radius: 6px; padding: 8px 12px; color: #365314; margin-top: 8px;">
                    <strong style="color: #1a2e05;">Recommended Remediation:</strong> ${escapeHtml(actionText)}
                </div>
            `;
        }

        html += `</div>`;
    });

    resultsContainer.innerHTML = html;
}

// ── Export SARIF v2.1.0 ─────────────────────────────────────────────────────
async function exportSarif() {
    try {
        const response = await fetch("/api/export/sarif", { method: "POST" });
        const sarifData = await response.json();
        const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `verification-report-${Date.now()}.sarif`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        alert("SARIF export failed: " + e.message);
    }
}

// ── Catalog Management ──────────────────────────────────────────────────────
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



// ── Rule 9: Live Fix Verification ("If You Didn't Fix It, It Ain't Fixed") ───
async function verifyFixWithRule9(btn) {
    const ruleId = btn.getAttribute("data-rule");
    const diff = decodeURIComponent(btn.getAttribute("data-diff"));
    const container = btn.closest(".diff-box").querySelector(".verify-output-container");
    const editor = document.getElementById("code-editor");
    if (!editor || !container) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Testing Rule 9...';

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
                        <strong>Agans Rule 9 Verified: "If You Didn't Fix It, It Ain't Fixed"</strong><br>
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
                        <strong>Agans Rule 9 Warning: Fix Incomplete or Regressed</strong><br>
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
        btn.innerHTML = '<span>✅</span> Verify Fix (Rule 9)';
    }
}

// ── Rule 7: Pre-Flight Baseline Sanity Checks ("Check the Plug") ─────────────
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
                    alert("🔌 Agans Rule 7 (Check the Plug) PASSED!\n\nAll basic prerequisites met:\n✓ Non-empty source buffer\n✓ Valid syntax tree\n✓ No literal zero denominators\n✓ Base contracts intact.");
                } else {
                    const issuesList = data.issues.map((iss, i) => `${i + 1}. [Line ${iss.line || 1}] ${iss.message}`).join("\n");
                    alert(`🔌 Agans Rule 7 (Check the Plug) Found ${data.sanity_issues_count} Basic Issue(s):\n\n${issuesList}\n\nFix these fundamental issues before running heavy symbolic analysis!`);
                }
            } catch (err) {
                alert("Check the Plug failed: " + err.message);
            } finally {
                btnCode.disabled = false;
                btnCode.innerHTML = '<span>🔌</span> Check the Plug (Rule 7)';
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
                    alert("🔌 Agans Rule 7 Failed: Netlist JSON syntax is invalid: " + e.message);
                    return;
                }
                const res = await fetch("/api/check-plug", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ netlist: netlistObj })
                });
                const data = await res.json();
                if (data.status === "PASS") {
                    alert("🔌 Agans Rule 7 (Check the Plug) PASSED!\n\nAll basic circuit prerequisites met:\n✓ Non-empty netlist structure\n✓ All gate inputs connected to valid drivers or supply rails\n✓ Power ground connectivity intact.");
                } else {
                    const issuesList = data.issues.map((iss, i) => `${i + 1}. ${iss.message}`).join("\n");
                    alert(`🔌 Agans Rule 7 (Check the Plug) Found ${data.sanity_issues_count} Basic Issue(s):\n\n${issuesList}`);
                }
            } catch (err) {
                alert("Check the Plug failed: " + err.message);
            } finally {
                btnCirc.disabled = false;
                btnCirc.innerHTML = '<span>🔌</span> Check the Plug (Rule 7)';
            }
        });
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

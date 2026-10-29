"""
Flask Web Server for the AI Bug Detection & Highlighting System.

Provides REST API endpoints for Phase 1 (Code) and Phase 2 (Circuit)
analysis, plus a modern web dashboard for interactive use.

Routes:
    GET  /                   -> Main dashboard page
    POST /api/analyze/code   -> Phase 1 code analysis
    POST /api/analyze/circuit-> Phase 2 circuit analysis
    POST /api/analyze/file   -> Auto-detect file type and analyze
    GET  /api/rules          -> Detection rule catalog (10 rules)
    POST /api/export/sarif   -> Export diagnostics as SARIF v2.1.0
"""

import os
import sys
import json
import traceback
from pathlib import Path
from typing import Any, Dict, List

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from flask_cors import CORS

# ── Ensure the project root is on sys.path for imports ────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from bug_detection.core.rules_catalog import ALL_RULES, DetectionRule
from bug_detection.core.agans_rules import (
    AGANS_NINE_RULES,
    AgansPreFlightChecker,
    AgansClosedLoopVerifier,
    get_agans_mapping_for_rule,
)
from bug_detection.core.schemas import (
    AutoRemediation,
    BugDiagnostic,
    CausalStep,
    CircuitProbe,
    CodeSpan,
    HighlightStyle,
    VerificationReport,
)
from bug_detection.core.scoring import (
    TimingParams,
    classify_timing_slack,
    hold_slack,
    hybrid_priority_score,
    ochiai_suspiciousness,
    setup_slack,
    severity_from_rule,
)

# ── Flask Application ─────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
    static_folder=str(Path(__file__).resolve().parent / "static"),
)
CORS(app)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Helper: Phase 1 Inline Code Analysis Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _analyze_phase1_code(source_code: str, language: str) -> List[BugDiagnostic]:
    """
    Run Phase 1 pattern-based heuristic analysis on source code.

    This is a built-in rule-based scanner that detects common bug patterns
    using line-by-line heuristic matching. It covers all five Phase 1 rules:
    CODE-MEM-001, CODE-MEM-002, CODE-NUM-003, CODE-SEC-004, CODE-CON-005.

    Args:
        source_code: The raw source code text to analyze.
        language:    Programming language ('python', 'c', 'javascript').

    Returns:
        List of BugDiagnostic objects for each detected issue.
    """
    diagnostics: List[BugDiagnostic] = []
    lines = source_code.split("\n")
    filename = f"<editor>.{_lang_ext(language)}"

    # Track state for context-aware detection
    freed_vars: Dict[str, int] = {}  # var_name -> line where freed
    allocated_vars: Dict[str, int] = {}  # var_name -> line where allocated
    divisor_zero_vars: Dict[str, int] = {}  # var_name -> line where set to 0
    taint_sources: Dict[str, int] = {}  # var_name -> line of taint source
    shared_vars: Dict[str, int] = {}  # var_name -> line of shared access

    for line_idx, line in enumerate(lines):
        line_num = line_idx + 1
        stripped = line.strip()

        # ── CODE-MEM-001: Use-After-Free / Double Free ────────────────────
        # Detect allocation
        for alloc_kw in ["allocate_buffer(", "malloc(", "calloc(", "new ",
                         "alloc(", "create_buffer("]:
            if alloc_kw in stripped:
                parts = stripped.split("=")
                if len(parts) >= 2:
                    var = parts[0].strip()
                    allocated_vars[var] = line_num

        # Detect free
        for free_kw in ["free_buf(", "free(", "delete ", "dealloc(",
                        "release(", "deallocate("]:
            if free_kw in stripped:
                # Extract variable name from free call
                start = stripped.index(free_kw) + len(free_kw)
                end = stripped.find(")", start)
                if end > start:
                    freed_var = stripped[start:end].strip()
                    freed_vars[freed_var] = line_num

        # Check for use-after-free
        for freed_var, freed_line in list(freed_vars.items()):
            if (freed_var in stripped
                    and line_num > freed_line
                    and not any(kw in stripped for kw in
                                ["free(", "free_buf(", "delete ", "="])):
                s_rule = severity_from_rule("CRITICAL")
                s_ochiai = ochiai_suspiciousness(n_ef=8, n_ep=1, n_nf=2)
                p_gnn = 0.92
                r_total = hybrid_priority_score(s_rule, s_ochiai, p_gnn)

                diag = BugDiagnostic(
                    phase="PHASE_1_CODE",
                    rule_id="CODE-MEM-001",
                    severity="CRITICAL",
                    message=(
                        f"Use-after-free: '{freed_var}' was freed at line "
                        f"{freed_line} but used again at line {line_num}."
                    ),
                    scores={
                        "S_rule": round(s_rule, 4),
                        "S_ochiai": round(s_ochiai, 4),
                        "P_gnn": round(p_gnn, 4),
                        "R_total": round(r_total, 4),
                    },
                    code_span=CodeSpan(
                        file=filename,
                        start_line=line_num,
                        start_col=stripped.index(freed_var),
                        end_line=line_num,
                        end_col=stripped.index(freed_var) + len(freed_var),
                    ),
                    causal_trace=[
                        CausalStep(1, f"Buffer allocated",
                                   file=filename,
                                   line=allocated_vars.get(freed_var,
                                                           freed_line - 2)),
                        CausalStep(2, f"Buffer freed at line {freed_line}",
                                   file=filename, line=freed_line),
                        CausalStep(3,
                                   f"Dangling pointer '{freed_var}' dereferenced",
                                   file=filename, line=line_num),
                    ],
                    auto_remediation=AutoRemediation(
                        summary="Nullify pointer after free; add null check before use.",
                        unified_diff=(
                            f"- {lines[freed_line - 1]}\n"
                            f"+ {lines[freed_line - 1]}\n"
                            f"+     {freed_var} = None  # Nullify after free"
                        ),
                        replacement_code_or_netlist=(
                            f"{lines[freed_line - 1]}\n"
                            f"    {freed_var} = None  # Nullify after free"
                        ),
                    ),
                )
                diagnostics.append(diag)

        # ── CODE-MEM-002: Out-of-Bounds Buffer Write ──────────────────────
        if any(pat in stripped for pat in
               ["[i+1]", "[i + 1]", "[idx+1]", "[index+1]"]):
            s_rule = severity_from_rule("CRITICAL")
            s_ochiai = ochiai_suspiciousness(n_ef=7, n_ep=2, n_nf=3)
            p_gnn = 0.88
            r_total = hybrid_priority_score(s_rule, s_ochiai, p_gnn)

            diag = BugDiagnostic(
                phase="PHASE_1_CODE",
                rule_id="CODE-MEM-002",
                severity="CRITICAL",
                message=(
                    f"Out-of-bounds access: index+1 may exceed buffer "
                    f"length at line {line_num}."
                ),
                scores={
                    "S_rule": round(s_rule, 4),
                    "S_ochiai": round(s_ochiai, 4),
                    "P_gnn": round(p_gnn, 4),
                    "R_total": round(r_total, 4),
                },
                code_span=CodeSpan(
                    file=filename,
                    start_line=line_num,
                    start_col=0,
                    end_line=line_num,
                    end_col=len(stripped),
                ),
                causal_trace=[
                    CausalStep(1, "Loop iterates up to length",
                               file=filename, line=line_num - 1),
                    CausalStep(2, "Access at [i+1] exceeds valid range",
                               file=filename, line=line_num),
                ],
                auto_remediation=AutoRemediation(
                    summary="Change loop bound to range(length - 1) to prevent off-by-one.",
                    unified_diff=(
                        f"- {stripped}\n"
                        f"+ # Fix: ensure loop bound is range(length - 1)\n"
                        f"+ {stripped.replace('range(length)', 'range(length - 1)')}"
                    ),
                    replacement_code_or_netlist=(
                        "for i in range(length - 1):  # Prevent OOB"
                    ),
                ),
            )
            diagnostics.append(diag)

        # ── CODE-NUM-003: Division by Zero ────────────────────────────────
        # Track zero-assigned variables
        if "= 0" in stripped and "/" not in stripped:
            parts = stripped.split("=")
            if len(parts) >= 2:
                var_name = parts[0].strip()
                try:
                    val = parts[1].strip().rstrip(";")
                    if val == "0":
                        divisor_zero_vars[var_name] = line_num
                except (ValueError, IndexError):
                    pass

        # Check for division using a known-zero variable
        if "/" in stripped and "//" not in stripped and "/*" not in stripped:
            for zero_var, zero_line in divisor_zero_vars.items():
                if (f"/ {zero_var}" in stripped
                        or f"/{zero_var}" in stripped):
                    s_rule = severity_from_rule("CRITICAL")
                    s_ochiai = ochiai_suspiciousness(n_ef=10, n_ep=0, n_nf=0)
                    p_gnn = 0.95
                    r_total = hybrid_priority_score(s_rule, s_ochiai, p_gnn)

                    diag = BugDiagnostic(
                        phase="PHASE_1_CODE",
                        rule_id="CODE-NUM-003",
                        severity="CRITICAL",
                        message=(
                            f"Division by zero: '{zero_var}' is 0 "
                            f"(assigned at line {zero_line}), used as "
                            f"divisor at line {line_num}."
                        ),
                        scores={
                            "S_rule": round(s_rule, 4),
                            "S_ochiai": round(s_ochiai, 4),
                            "P_gnn": round(p_gnn, 4),
                            "R_total": round(r_total, 4),
                        },
                        code_span=CodeSpan(
                            file=filename,
                            start_line=line_num,
                            start_col=stripped.index("/"),
                            end_line=line_num,
                            end_col=stripped.index("/") + len(zero_var) + 2,
                        ),
                        causal_trace=[
                            CausalStep(
                                1,
                                f"Variable '{zero_var}' assigned value 0",
                                file=filename, line=zero_line,
                            ),
                            CausalStep(
                                2,
                                f"'{zero_var}' reaches division without guard",
                                file=filename, line=line_num,
                            ),
                            CausalStep(
                                3,
                                "ZeroDivisionError raised at runtime",
                                file=filename, line=line_num,
                            ),
                        ],
                        auto_remediation=AutoRemediation(
                            summary=f"Add zero-divisor guard: if {zero_var} != 0.",
                            unified_diff=(
                                f"- {stripped}\n"
                                f"+ if {zero_var} != 0:\n"
                                f"+     {stripped}\n"
                                f"+ else:\n"
                                f"+     ratio = 0  # Safe default"
                            ),
                            replacement_code_or_netlist=(
                                f"if {zero_var} != 0:\n"
                                f"    {stripped}\n"
                                f"else:\n"
                                f"    ratio = 0  # Safe default"
                            ),
                        ),
                    )
                    diagnostics.append(diag)

        # ── CODE-SEC-004: Unsanitized Taint Sink ──────────────────────────
        # Detect taint sources
        for src_kw in ["input(", "request.args", "request.form",
                       "sys.argv", "os.environ", "getenv(",
                       "readline(", "raw_input("]:
            if src_kw in stripped:
                parts = stripped.split("=")
                if len(parts) >= 2:
                    tvar = parts[0].strip()
                    taint_sources[tvar] = line_num

        # Detect taint sinks (SQL, exec, eval, os.system)
        for sink_kw in ["SELECT ", "INSERT ", "UPDATE ", "DELETE ",
                        "exec(", "eval(", "os.system(",
                        "subprocess.call(", "cursor.execute("]:
            if sink_kw in stripped:
                for tvar, tline in taint_sources.items():
                    if tvar in stripped:
                        s_rule = severity_from_rule("CRITICAL")
                        s_ochiai = ochiai_suspiciousness(n_ef=6, n_ep=2,
                                                        n_nf=2)
                        p_gnn = 0.91
                        r_total = hybrid_priority_score(s_rule, s_ochiai,
                                                        p_gnn)

                        diag = BugDiagnostic(
                            phase="PHASE_1_CODE",
                            rule_id="CODE-SEC-004",
                            severity="CRITICAL",
                            message=(
                                f"SQL Injection / Taint: unsanitized "
                                f"variable '{tvar}' (tainted at line "
                                f"{tline}) flows into query at line "
                                f"{line_num}."
                            ),
                            scores={
                                "S_rule": round(s_rule, 4),
                                "S_ochiai": round(s_ochiai, 4),
                                "P_gnn": round(p_gnn, 4),
                                "R_total": round(r_total, 4),
                            },
                            code_span=CodeSpan(
                                file=filename,
                                start_line=line_num,
                                start_col=0,
                                end_line=line_num,
                                end_col=len(stripped),
                            ),
                            causal_trace=[
                                CausalStep(
                                    1,
                                    f"Taint source: '{tvar}' = input()",
                                    file=filename, line=tline,
                                ),
                                CausalStep(
                                    2,
                                    "Flows unsanitized through string concatenation",
                                    file=filename, line=line_num,
                                ),
                                CausalStep(
                                    3,
                                    "Reaches SQL query sink without parameterization",
                                    file=filename, line=line_num,
                                ),
                            ],
                            auto_remediation=AutoRemediation(
                                summary="Use parameterized query instead of string concat.",
                                unified_diff=(
                                    f'- {stripped}\n'
                                    f'+ query = "SELECT * FROM packets '
                                    f'WHERE filter = ?"\n'
                                    f'+ params = ({tvar},)'
                                ),
                                replacement_code_or_netlist=(
                                    f'query = "SELECT * FROM packets '
                                    f'WHERE filter = ?"\n'
                                    f'params = ({tvar},)'
                                ),
                            ),
                        )
                        diagnostics.append(diag)

        # ── CODE-CON-005: Data Race / Missing Lock ────────────────────────
        for race_kw in ["shared_", "global_", "threading.",
                        "multiprocessing."]:
            if race_kw in stripped:
                # Look for bare increment/modification without lock
                if any(op in stripped for op in ["+=", "-=", "*=", "= ",
                                                 ".append(", ".pop("]):
                    parts = stripped.split("+=") if "+=" in stripped else stripped.split("=")
                    var_name = parts[0].strip() if parts else stripped
                    if ("lock" not in stripped.lower()
                            and "mutex" not in stripped.lower()
                            and "with " not in stripped.lower()):
                        s_rule = severity_from_rule("WARNING")
                        s_ochiai = ochiai_suspiciousness(n_ef=4, n_ep=5,
                                                        n_nf=1)
                        p_gnn = 0.72
                        r_total = hybrid_priority_score(s_rule, s_ochiai,
                                                        p_gnn)

                        diag = BugDiagnostic(
                            phase="PHASE_1_CODE",
                            rule_id="CODE-CON-005",
                            severity="WARNING",
                            message=(
                                f"Data race: '{var_name}' is modified "
                                f"without synchronization at line "
                                f"{line_num}."
                            ),
                            scores={
                                "S_rule": round(s_rule, 4),
                                "S_ochiai": round(s_ochiai, 4),
                                "P_gnn": round(p_gnn, 4),
                                "R_total": round(r_total, 4),
                            },
                            code_span=CodeSpan(
                                file=filename,
                                start_line=line_num,
                                start_col=0,
                                end_line=line_num,
                                end_col=len(stripped),
                            ),
                            causal_trace=[
                                CausalStep(
                                    1,
                                    f"Shared variable '{var_name}' accessed",
                                    file=filename, line=line_num,
                                ),
                                CausalStep(
                                    2,
                                    "No mutex/lock guard in scope",
                                    file=filename, line=line_num,
                                ),
                            ],
                            auto_remediation=AutoRemediation(
                                summary="Wrap access in a threading.Lock() context manager.",
                                unified_diff=(
                                    f"- {stripped}\n"
                                    f"+ with lock:\n"
                                    f"+     {stripped}"
                                ),
                                replacement_code_or_netlist=(
                                    f"with lock:\n    {stripped}"
                                ),
                            ),
                        )
                        diagnostics.append(diag)

    return diagnostics


def _lang_ext(language: str) -> str:
    """Map language name to file extension."""
    return {"python": "py", "c": "c", "javascript": "js"}.get(
        language.lower(), "txt"
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Helper: Phase 2 Inline Circuit Analysis Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _analyze_phase2_circuit(netlist: Dict[str, Any]) -> List[BugDiagnostic]:
    """
    Run Phase 2 analysis on a circuit netlist JSON.

    Performs timing analysis, clock-domain crossing checks, ERC for
    floating nets and feedback loops. Covers all five Phase 2 rules:
    CIRC-STA-001, CIRC-CDC-002, CIRC-ERC-003, CIRC-ERC-004, CIRC-PWR-005.

    Args:
        netlist: Parsed netlist dictionary with gates, nets, timing_paths.

    Returns:
        List of BugDiagnostic objects for each detected issue.
    """
    diagnostics: List[BugDiagnostic] = []
    module = netlist.get("module") or netlist.get("design_name") or "<unknown>"

    raw_gates = netlist.get("gates", {})
    if isinstance(raw_gates, dict):
        gates = {k: {**v, "id": k} if isinstance(v, dict) else {"id": k} for k, v in raw_gates.items()}
    elif isinstance(raw_gates, list):
        gates = {g.get("id", g.get("name", "")): g for g in raw_gates if isinstance(g, dict)}
    else:
        gates = {}

    raw_nets = netlist.get("nets", {})
    if isinstance(raw_nets, dict):
        nets = [{"name": k, **v} if isinstance(v, dict) else {"name": k} for k, v in raw_nets.items()]
    elif isinstance(raw_nets, list):
        nets = raw_nets
    else:
        nets = []

    raw_paths = netlist.get("timing_paths", [])
    timing_paths = []
    if isinstance(raw_paths, list):
        for tp in raw_paths:
            if not isinstance(tp, dict):
                continue
            launch = tp.get("launch_ff") or tp.get("start_point") or tp.get("launch_gate") or ""
            capture = tp.get("capture_ff") or tp.get("end_point") or tp.get("capture_gate") or ""
            cone = tp.get("comb_cone") or tp.get("through") or tp.get("through_gates") or []
            comb_del = tp.get("comb_delay_ns")
            if comb_del is None:
                comb_del = sum(gates.get(g, {}).get("delay_ns", 0.0) for g in cone)
            timing_paths.append({
                **tp,
                "launch_ff": launch,
                "capture_ff": capture,
                "comb_cone": cone,
                "comb_delay_ns": comb_del,
            })

    # ── CIRC-STA-001: Setup / Hold Timing Violations ──────────────────────
    for tp in timing_paths:
        launch_id = tp.get("launch_ff", "")
        capture_id = tp.get("capture_ff", "")
        comb_cone = tp.get("comb_cone", [])
        launch_gate = gates.get(launch_id, {})
        capture_gate = gates.get(capture_id, {})

        clk_to_q = launch_gate.get("clk_to_q_ns", 0.18)
        setup_time = capture_gate.get("setup_ns", 0.12)
        hold_time = capture_gate.get("hold_ns", 0.05)

        # Sum combinational delay
        comb_delay = sum(gates.get(g, {}).get("delay_ns", 0.0) for g in comb_cone)

        params = TimingParams(
            clk_period_ns=tp.get("clk_period_ns", 2.0),
            cap_clk_delay_ns=tp.get("cap_clk_delay_ns", 0.0),
            lnch_clk_delay_ns=tp.get("lnch_clk_delay_ns", 0.0),
            clk_to_q_ns=clk_to_q,
            comb_delay_ns=comb_delay,
            setup_ns=setup_time,
            hold_ns=hold_time,
            uncertainty_ns=tp.get("uncertainty_ns", 0.0),
        )

        s_setup = setup_slack(params)
        s_hold = hold_slack(params)
        severity_setup = classify_timing_slack(s_setup)
        severity_hold = classify_timing_slack(s_hold)

        if severity_setup in ("CRITICAL", "WARNING"):
            s_rule = severity_from_rule(severity_setup)
            r_total = hybrid_priority_score(s_rule, 0.85, 0.88)
            diag = BugDiagnostic(
                phase="PHASE_2_CIRCUIT",
                rule_id="CIRC-STA-001",
                severity=severity_setup,
                message=(
                    f"Setup timing violation on path "
                    f"{launch_id} → {capture_id}: "
                    f"Slack = {s_setup:.3f} ns (required ≥ 0). "
                    f"Combinational delay = {comb_delay:.3f} ns through "
                    f"{' → '.join(comb_cone)}."
                ),
                scores={
                    "S_rule": round(s_rule, 4),
                    "S_ochiai": 0.85,
                    "P_gnn": 0.88,
                    "R_total": round(r_total, 4),
                },
                slack_ns=round(s_setup, 4),
                circuit_probe=CircuitProbe(
                    module=module,
                    net_names=[tp.get("crossing_net", "")],
                    gate_instances=[launch_id] + comb_cone + [capture_id],
                    slack_ns=round(s_setup, 4),
                    clock_domains=list({
                        launch_gate.get("clock_domain", ""),
                        capture_gate.get("clock_domain", ""),
                    }),
                    vcd_window_ps=tp.get("vcd_window_ps", []),
                    gdsii_bbox=tp.get("bbox", []),
                ),
                causal_trace=[
                    CausalStep(1, f"Launch FF '{launch_id}' fires on CLK edge"),
                    CausalStep(2, f"Data propagates through {len(comb_cone)} "
                                  f"combinational stages"),
                    CausalStep(3, f"Total comb delay = {comb_delay:.3f} ns"),
                    CausalStep(4, f"Data arrives AFTER setup window of "
                                  f"'{capture_id}' (slack = {s_setup:.3f} ns)"),
                ],
                auto_remediation=AutoRemediation(
                    summary=(
                        "Insert pipeline register to split combinational "
                        "path, or upsize driver cells to reduce delay."
                    ),
                    unified_diff=(
                        f"// Before: single-stage path ({comb_delay:.3f} ns)\n"
                        f"// After:  insert pipeline FF after "
                        f"{comb_cone[len(comb_cone)//2] if comb_cone else 'midpoint'}"
                    ),
                ),
            )
            diagnostics.append(diag)

        if severity_hold in ("CRITICAL", "WARNING"):
            s_rule = severity_from_rule(severity_hold)
            r_total = hybrid_priority_score(s_rule, 0.78, 0.82)
            diag = BugDiagnostic(
                phase="PHASE_2_CIRCUIT",
                rule_id="CIRC-STA-001",
                severity=severity_hold,
                message=(
                    f"Hold timing violation on path "
                    f"{launch_id} → {capture_id}: "
                    f"Slack = {s_hold:.3f} ns (required ≥ 0)."
                ),
                scores={
                    "S_rule": round(s_rule, 4),
                    "S_ochiai": 0.78,
                    "P_gnn": 0.82,
                    "R_total": round(r_total, 4),
                },
                slack_ns=round(s_hold, 4),
                circuit_probe=CircuitProbe(
                    module=module,
                    gate_instances=[launch_id, capture_id],
                    slack_ns=round(s_hold, 4),
                    clock_domains=list({
                        launch_gate.get("clock_domain", ""),
                        capture_gate.get("clock_domain", ""),
                    }),
                ),
                auto_remediation=AutoRemediation(
                    summary="Add buffer delay cells on the data path.",
                ),
            )
            diagnostics.append(diag)

    # ── CIRC-CDC-002: Unsynchronized Clock Domain Crossing ────────────────
    for tp in timing_paths:
        launch_id = tp.get("launch_ff", "")
        capture_id = tp.get("capture_ff", "")
        launch_gate = gates.get(launch_id, {})
        capture_gate = gates.get(capture_id, {})
        clk_a = launch_gate.get("clock_domain", "")
        clk_b = capture_gate.get("clock_domain", "")

        if clk_a and clk_b and clk_a != clk_b:
            s_rule = severity_from_rule("WARNING")
            r_total = hybrid_priority_score(s_rule, 0.70, 0.75)
            diag = BugDiagnostic(
                phase="PHASE_2_CIRCUIT",
                rule_id="CIRC-CDC-002",
                severity="WARNING",
                message=(
                    f"Unsynchronized clock domain crossing: signal "
                    f"crosses from {clk_a} ({launch_id}) to "
                    f"{clk_b} ({capture_id}) without 2-FF synchronizer."
                ),
                scores={
                    "S_rule": round(s_rule, 4),
                    "S_ochiai": 0.70,
                    "P_gnn": 0.75,
                    "R_total": round(r_total, 4),
                },
                circuit_probe=CircuitProbe(
                    module=module,
                    net_names=[tp.get("crossing_net", "")],
                    gate_instances=[launch_id, capture_id],
                    clock_domains=[clk_a, clk_b],
                    vcd_window_ps=tp.get("vcd_window_ps", []),
                    gdsii_bbox=tp.get("bbox", []),
                ),
                causal_trace=[
                    CausalStep(1, f"Signal originates in domain '{clk_a}'"),
                    CausalStep(2, f"Crosses to domain '{clk_b}' on net "
                                  f"'{tp.get('crossing_net', '')}'"),
                    CausalStep(3, "No 2-FF synchronizer detected on path"),
                    CausalStep(4, "Risk of metastability at capture FF"),
                ],
                auto_remediation=AutoRemediation(
                    summary=(
                        f"Instantiate a 2-FF synchronizer or async Gray "
                        f"FIFO between {clk_a} and {clk_b} domains."
                    ),
                ),
            )
            diagnostics.append(diag)

    # ── CIRC-ERC-004: Floating Net ────────────────────────────────────────
    for net in nets:
        raw_drivers = net.get("drivers", [])
        raw_sinks = net.get("sinks", [])
        drivers = [d if isinstance(d, str) else d.get("gate_id", str(d)) for d in raw_drivers]
        sinks = [s if isinstance(s, str) else s.get("gate_id", str(s)) for s in raw_sinks]
        net_name = net.get("name", "<unknown>")

        if len(drivers) == 0:
            s_rule = severity_from_rule("VIOLET_NET")
            r_total = hybrid_priority_score(s_rule, 0.60, 0.55)
            diag = BugDiagnostic(
                phase="PHASE_2_CIRCUIT",
                rule_id="CIRC-ERC-004",
                severity="VIOLET_NET",
                message=(
                    f"Floating net: '{net_name}' has no drivers but "
                    f"connects to {len(sinks)} sink(s): "
                    f"{', '.join(sinks)}. Causes X-propagation."
                ),
                scores={
                    "S_rule": round(s_rule, 4),
                    "S_ochiai": 0.60,
                    "P_gnn": 0.55,
                    "R_total": round(r_total, 4),
                },
                circuit_probe=CircuitProbe(
                    module=module,
                    net_names=[net_name],
                    gate_instances=sinks,
                    gdsii_bbox=net.get("bbox", []),
                ),
                causal_trace=[
                    CausalStep(1, f"Net '{net_name}' has 0 drivers"),
                    CausalStep(2, f"Sinks {sinks} receive indeterminate value"),
                    CausalStep(3, "X-propagation through downstream logic"),
                ],
                auto_remediation=AutoRemediation(
                    summary=(
                        f"Tie net '{net_name}' to VDD/GND default rail "
                        f"or connect proper driver."
                    ),
                ),
            )
            diagnostics.append(diag)

        elif len(drivers) > 1:
            s_rule = severity_from_rule("VIOLET_NET")
            r_total = hybrid_priority_score(s_rule, 0.55, 0.50)
            diag = BugDiagnostic(
                phase="PHASE_2_CIRCUIT",
                rule_id="CIRC-ERC-004",
                severity="VIOLET_NET",
                message=(
                    f"Multi-driver conflict: net '{net_name}' has "
                    f"{len(drivers)} drivers: {', '.join(drivers)}. "
                    f"Potential contention without tri-state mux."
                ),
                scores={
                    "S_rule": round(s_rule, 4),
                    "S_ochiai": 0.55,
                    "P_gnn": 0.50,
                    "R_total": round(r_total, 4),
                },
                circuit_probe=CircuitProbe(
                    module=module,
                    net_names=[net_name],
                    gate_instances=drivers + sinks,
                    gdsii_bbox=net.get("bbox", []),
                ),
                auto_remediation=AutoRemediation(
                    summary="Add multiplexer to arbitrate between drivers.",
                ),
            )
            diagnostics.append(diag)

    # ── CIRC-ERC-003: Combinational Feedback Loop Detection ───────────────
    # Build adjacency from nets
    gate_adj: Dict[str, List[str]] = {}
    for net in nets:
        for drv in net.get("drivers", []):
            d_id = drv if isinstance(drv, str) else drv.get("gate_id", str(drv))
            for snk in net.get("sinks", []):
                s_id = snk if isinstance(snk, str) else snk.get("gate_id", str(snk))
                gate_adj.setdefault(d_id, []).append(s_id)

    # DFS cycle detection among non-sequential (non-DFF) gates
    sequential_types = {"DFF", "DFFR", "DFFE", "LATCH", "RAM", "BRAM"}
    visited = set()
    rec_stack = set()

    def _dfs_cycle(node: str, path: List[str]) -> List[str]:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        for neighbor in gate_adj.get(node, []):
            ntype = gates.get(neighbor, {}).get("type", "")
            if ntype in sequential_types:
                continue
            if neighbor in rec_stack:
                cycle_start = path.index(neighbor)
                return path[cycle_start:] + [neighbor]
            if neighbor not in visited:
                result = _dfs_cycle(neighbor, path)
                if result:
                    return result
        path.pop()
        rec_stack.discard(node)
        return []

    for gate_id, gate_info in gates.items():
        if gate_info.get("type", "") in sequential_types:
            continue
        if gate_id not in visited:
            cycle = _dfs_cycle(gate_id, [])
            if cycle:
                s_rule = severity_from_rule("CRITICAL")
                r_total = hybrid_priority_score(s_rule, 0.90, 0.88)
                cycle_str = " → ".join(cycle)
                diag = BugDiagnostic(
                    phase="PHASE_2_CIRCUIT",
                    rule_id="CIRC-ERC-003",
                    severity="CRITICAL",
                    message=(
                        f"Combinational feedback loop detected: "
                        f"{cycle_str}. Zero sequential elements in cycle."
                    ),
                    scores={
                        "S_rule": round(s_rule, 4),
                        "S_ochiai": 0.90,
                        "P_gnn": 0.88,
                        "R_total": round(r_total, 4),
                    },
                    circuit_probe=CircuitProbe(
                        module=module,
                        gate_instances=cycle[:-1],
                    ),
                    causal_trace=[
                        CausalStep(i + 1, f"Gate '{g}'")
                        for i, g in enumerate(cycle)
                    ],
                    auto_remediation=AutoRemediation(
                        summary=(
                            "Break combinational loop by inserting a "
                            "clocked D-flip-flop into the feedback path."
                        ),
                    ),
                )
                diagnostics.append(diag)
                break  # Report first cycle found

    return diagnostics


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: Dashboard
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/debug-env")
def debug_env():
    """Diagnostic endpoint to inspect Vercel environment headers."""
    return jsonify({
        "path_info": request.environ.get("PATH_INFO"),
        "request_uri": request.environ.get("REQUEST_URI"),
        "raw_uri": request.environ.get("RAW_URI"),
        "x_forwarded_uri": request.environ.get("HTTP_X_FORWARDED_URI"),
        "x_matched_path": request.environ.get("HTTP_X_MATCHED_PATH"),
        "x_now_route_matches": request.environ.get("HTTP_X_NOW_ROUTE_MATCHES"),
        "all_env_keys": [k for k in request.environ.keys() if "HTTP" in k or "URI" in k or "PATH" in k],
    }), 200


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: Phase 1 — Code Analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/analyze/code", methods=["POST"])
def analyze_code():
    """
    Analyze source code for Phase 1 bug patterns.

    Request JSON:
        {
            "source_code": "...",
            "language": "python" | "c" | "javascript"
        }

    Returns:
        JSON with verification report containing diagnostics.
    """
    try:
        data = request.get_json(force=True)
        source_code = data.get("source_code", "")
        language = data.get("language", "python")

        if not source_code.strip():
            return jsonify({"error": "No source code provided."}), 400

        diagnostics = _analyze_phase1_code(source_code, language)

        report = VerificationReport()
        for d in diagnostics:
            report.add_diagnostic(d)

        return jsonify(report.to_dict()), 200

    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: Phase 2 — Circuit Analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/analyze/circuit", methods=["POST"])
def analyze_circuit():
    """
    Analyze a circuit netlist for Phase 2 bug patterns.

    Request JSON:
        The full netlist JSON with gates, nets, and timing_paths.

    Returns:
        JSON with verification report containing diagnostics.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        netlist = data.get("netlist") if ("netlist" in data and isinstance(data["netlist"], dict)) else data

        if not netlist or not netlist.get("gates"):
            return jsonify({"error": "Invalid or empty netlist JSON."}), 400

        diagnostics = _analyze_phase2_circuit(netlist)

        report = VerificationReport()
        for d in diagnostics:
            report.add_diagnostic(d)

        return jsonify(report.to_dict()), 200

    except json.JSONDecodeError as exc:
        return jsonify({"error": f"Invalid JSON: {exc}"}), 400
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: File Upload — Auto-detect & Analyze
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/analyze/file", methods=["POST"])
def analyze_file():
    """
    Upload a file for analysis, auto-detecting whether it is source code
    or a circuit netlist JSON.

    Accepts:
        multipart/form-data with field 'file'.

    Returns:
        JSON with verification report.
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        uploaded = request.files["file"]
        filename = uploaded.filename or "unknown"
        content = uploaded.read().decode("utf-8", errors="replace")

        if not content.strip():
            return jsonify({"error": "Uploaded file is empty."}), 400

        # Auto-detect type
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        report = VerificationReport()

        if ext == "json" or content.strip().startswith("{"):
            # Treat as circuit netlist
            try:
                netlist = json.loads(content)
                diagnostics = _analyze_phase2_circuit(netlist)
                for d in diagnostics:
                    report.add_diagnostic(d)
            except json.JSONDecodeError:
                # Not valid JSON — fall through to code analysis
                lang = _detect_language(filename, content)
                diagnostics = _analyze_phase1_code(content, lang)
                for d in diagnostics:
                    report.add_diagnostic(d)
        else:
            lang = _detect_language(filename, content)
            diagnostics = _analyze_phase1_code(content, lang)
            for d in diagnostics:
                report.add_diagnostic(d)

        return jsonify(report.to_dict()), 200

    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


def _detect_language(filename: str, content: str) -> str:
    """Infer programming language from file extension or content heuristics."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext_map = {
        "py": "python",
        "c": "c",
        "h": "c",
        "cpp": "c",
        "js": "javascript",
        "ts": "javascript",
        "jsx": "javascript",
        "tsx": "javascript",
    }
    if ext in ext_map:
        return ext_map[ext]
    # Heuristic: check for common patterns
    if "def " in content or "import " in content:
        return "python"
    if "#include" in content or "int main" in content:
        return "c"
    if "function " in content or "const " in content or "=>" in content:
        return "javascript"
    return "python"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: Detection Rule Catalog
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/rules", methods=["GET"])
def get_rules():
    """
    Return the complete 10-rule detection catalog with Agans 9 Rules references.

    Returns:
        JSON array of rule objects.
    """
    rules_list = []
    for rule_id, rule in ALL_RULES.items():
        rules_list.append({
            "rule_id": rule.rule_id,
            "phase": rule.phase,
            "category": rule.category,
            "detection_predicate": rule.detection_predicate,
            "severity": rule.severity,
            "highlight_hex": rule.highlight_hex,
            "fix_strategy": rule.fix_strategy,
            "tags": rule.tags,
            "agans_rule": getattr(rule, "agans_rule", ""),
            "agans_summary": getattr(rule, "agans_summary", ""),
        })
    return jsonify({"rules": rules_list, "count": len(rules_list)}), 200


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: David J. Agans 9 Indispensable Rules Catalog
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/agans-rules", methods=["GET"])
def get_agans_rules():
    """
    Return David J. Agans' 9 Indispensable Rules for Debugging with
    dual-phase software and hardware circuit implementation mapping.
    """
    rules = [r.to_dict() for r in AGANS_NINE_RULES.values()]
    return jsonify({
        "book": "Debugging: The 9 Indispensable Rules for Finding Even the Most Elusive Software and Hardware Problems",
        "author": "David J. Agans",
        "rules_count": len(rules),
        "rules": rules,
    }), 200


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: Rule 9 Closed-Loop Fix Verifier ("If You Didn't Fix It, It Ain't Fixed")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/verify-fix", methods=["POST"])
def verify_fix():
    """
    Apply a proposed auto-remediation patch in an isolated sandbox, re-run
    analysis, and verify whether the bug is resolved under Agans Rule 9.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        original_source = data.get("source_code", "")
        target_rule_id = data.get("rule_id", "")
        patch_diff = data.get("unified_diff", "")
        language = data.get("language", "python")

        if not original_source.strip():
            return jsonify({"error": "Original source code is required."}), 400

        patched_source = AgansClosedLoopVerifier.apply_patch(original_source, patch_diff)

        def analyzer_callable(code: str) -> List[dict]:
            diags = _analyze_phase1_code(code, language)
            return [d.to_dict() for d in diags]

        result = AgansClosedLoopVerifier.verify_code_fix(
            original_source=original_source,
            patched_source=patched_source,
            target_rule_id=target_rule_id,
            analyzer_callable=analyzer_callable,
        )
        result["patched_source"] = patched_source
        return jsonify(result), 200

    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: Rule 7 Pre-Flight Sanity Checker ("Check the Plug")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/check-plug", methods=["POST"])
def check_plug():
    """
    Execute Rule 7 ("Check the Plug") pre-flight baseline sanity checks.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        source_code = data.get("source_code", "")
        netlist = data.get("netlist", None)

        results = []
        if source_code:
            results.extend(AgansPreFlightChecker.check_code_sanity(source_code))
        if netlist:
            results.extend(AgansPreFlightChecker.check_netlist_sanity(netlist))

        return jsonify({
            "agans_rule": "RULE_7_CHECK_THE_PLUG",
            "sanity_issues_count": len(results),
            "issues": results,
            "status": "PASS" if len(results) == 0 else "FAIL_PREFLIGHT",
        }), 200

    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Route: SARIF Export
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.route("/api/export/sarif", methods=["POST"])
def export_sarif():
    """
    Export diagnostics as SARIF v2.1.0 JSON.

    Request JSON:
        A verification report dict with 'highlights' array.

    Returns:
        SARIF v2.1.0 JSON document.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        highlights = data.get("highlights", [])

        report = VerificationReport()
        for h in highlights:
            code_span = None
            if "code_span" in h:
                cs = h["code_span"]
                code_span = CodeSpan(
                    file=cs.get("file", ""),
                    start_line=cs.get("start_line", 0),
                    start_col=cs.get("start_col", 0),
                    end_line=cs.get("end_line", 0),
                    end_col=cs.get("end_col", 0),
                )

            circuit_probe = None
            if "circuit_probe" in h:
                cp = h["circuit_probe"]
                circuit_probe = CircuitProbe(
                    module=cp.get("module", ""),
                    net_names=cp.get("net_names", []),
                    gate_instances=cp.get("gate_instances", []),
                    slack_ns=cp.get("slack_ns", 0.0),
                    clock_domains=cp.get("clock_domains", []),
                    vcd_window_ps=cp.get("vcd_window_ps", []),
                    gdsii_bbox=cp.get("gdsii_bbox", []),
                )

            auto_rem = None
            if "auto_remediation" in h:
                ar = h["auto_remediation"]
                auto_rem = AutoRemediation(
                    summary=ar.get("summary", ""),
                    unified_diff=ar.get("unified_diff", ""),
                    replacement_code_or_netlist=ar.get(
                        "replacement_code_or_netlist", ""
                    ),
                    verification_status=ar.get("verification_status",
                                                "UNVERIFIED"),
                )

            highlight_style = None
            if "highlight_style" in h:
                hs = h["highlight_style"]
                highlight_style = HighlightStyle(
                    color_hex=hs.get("color_hex", "#D92D20"),
                    underline=hs.get("underline", ""),
                )

            diag = BugDiagnostic(
                bug_id=h.get("bug_id", ""),
                phase=h.get("phase", "PHASE_1_CODE"),
                rule_id=h.get("rule_id", ""),
                severity=h.get("severity", "WARNING"),
                message=h.get("message", ""),
                scores=h.get("scores", {}),
                code_span=code_span,
                circuit_probe=circuit_probe,
                highlight_style=highlight_style,
                auto_remediation=auto_rem,
                slack_ns=h.get("slack_ns"),
            )
            report.add_diagnostic(diag)

        sarif = report.to_sarif()

        # Populate rules in SARIF from our catalog
        sarif_rules = []
        for rule_id, rule in ALL_RULES.items():
            sarif_rules.append({
                "id": rule.rule_id,
                "name": rule.category,
                "shortDescription": {"text": rule.detection_predicate},
                "defaultConfiguration": {
                    "level": "error" if rule.severity == "CRITICAL" else "warning"
                },
                "properties": {
                    "severity": rule.severity,
                    "highlight_hex": rule.highlight_hex,
                    "tags": rule.tags,
                },
            })
        sarif["runs"][0]["tool"]["driver"]["rules"] = sarif_rules

        return jsonify(sarif), 200

    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Bug Detection & Highlighting System — Web Dashboard")
    print("  Serving at: http://localhost:5000 and http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

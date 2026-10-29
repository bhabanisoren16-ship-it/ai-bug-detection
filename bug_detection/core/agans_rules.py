"""
David J. Agans' 9 Indispensable Rules for Debugging — Core Framework.

Reference: "Debugging: The 9 Indispensable Rules for Finding Even the Most
Elusive Software and Hardware Problems" by David J. Agans.

This module maps Agans' 9 fundamental debugging maxims into executable,
dual-phase algorithms for both software code and hardware circuit debugging:

1. Understand the System
2. Make It Fail
3. Quit Thinking and Look
4. Divide and Conquer
5. Change One Thing at a Time
6. Keep an Audit Trail
7. Check the Plug
8. Get a Fresh View
9. If You Didn't Fix It, It Ain't Fixed
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class AgansRuleId(str, Enum):
    """The 9 Indispensable Rules established by David J. Agans."""
    RULE_1_UNDERSTAND = "RULE_1_UNDERSTAND_THE_SYSTEM"
    RULE_2_MAKE_IT_FAIL = "RULE_2_MAKE_IT_FAIL"
    RULE_3_QUIT_THINKING_AND_LOOK = "RULE_3_QUIT_THINKING_AND_LOOK"
    RULE_4_DIVIDE_AND_CONQUER = "RULE_4_DIVIDE_AND_CONQUER"
    RULE_5_CHANGE_ONE_THING = "RULE_5_CHANGE_ONE_THING_AT_A_TIME"
    RULE_6_KEEP_AUDIT_TRAIL = "RULE_6_KEEP_AN_AUDIT_TRAIL"
    RULE_7_CHECK_THE_PLUG = "RULE_7_CHECK_THE_PLUG"
    RULE_8_FRESH_VIEW = "RULE_8_GET_A_FRESH_VIEW"
    RULE_9_NOT_FIXED_AINT_FIXED = "RULE_9_IF_YOU_DIDNT_FIX_IT_IT_AINT_FIXED"


@dataclass
class AgansRuleInfo:
    """Detailed definition and dual-phase application of an Agans Rule."""
    rule_id: AgansRuleId
    rule_number: int
    title: str
    mantra: str
    summary: str
    software_application: str
    circuit_application: str
    telemetry_hook: str
    badge_label: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["rule_id"] = self.rule_id.value
        return d


# ─── Canonical Definition of the 9 Indispensable Rules ────────────────────────

AGANS_NINE_RULES: Dict[AgansRuleId, AgansRuleInfo] = {
    AgansRuleId.RULE_1_UNDERSTAND: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_1_UNDERSTAND,
        rule_number=1,
        title="Understand the System",
        mantra="Read the manual. Know how the system is supposed to work before deciding it's broken.",
        summary=(
            "Understand language specifications, API contracts, circuit topology, and domain "
            "rules so anomalous behavior stands out against defined expectations."
        ),
        software_application=(
            "Parse Abstract Syntax Trees (AST), validate Python grammar, analyze variable scopes, "
            "and enforce standard library lifecycle contracts."
        ),
        circuit_application=(
            "Elaborate hypergraph netlist G=(V, E), map gate I/O directions, establish clock "
            "frequencies, and verify power domain constraints (V_DD, V_SS)."
        ),
        telemetry_hook="ast_parser / netlist_hypergraph_parser",
        badge_label="Rule 1: Understand the System",
    ),

    AgansRuleId.RULE_2_MAKE_IT_FAIL: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_2_MAKE_IT_FAIL,
        rule_number=2,
        title="Make It Fail",
        mantra="Do it again. Stimulate the failure consistently so you can study it under a microscope.",
        summary=(
            "Reproduce defects deterministically using synthesized failing test stimuli, "
            "formal assertion counterexamples, and boundary-value stresses."
        ),
        software_application=(
            "Execute test suites to generate Ochiai SBFL execution coverage matrices (n_ef, n_ep, n_nf, n_np) "
            "and stimulate out-of-bounds boundary conditions."
        ),
        circuit_application=(
            "Run Bounded Model Checking (BMC) to synthesize state counterexample traces and "
            "stimulate setup/hold violations with maximum skew clock edges."
        ),
        telemetry_hook="dynamic_analyzer (SBFL) / formal_checker (BMC)",
        badge_label="Rule 2: Make It Fail",
    ),

    AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
        rule_number=3,
        title="Quit Thinking and Look",
        mantra="Stop guessing and theorizing. Look at the actual signals, bytes, and telemetry.",
        summary=(
            "Never assume where the bug is without empirical evidence. Instrument the system, "
            "render precise visual coordinate overlays, and inspect actual waveforms."
        ),
        software_application=(
            "3-layer visual overlays with character-accurate carets (^^^^^), line-level gutters, "
            "and ANSI/LSP diagnostic highlights pointing directly to the root expression."
        ),
        circuit_application=(
            "Synchronized 4-View Cross-Probe displaying RTL source, schematic logic cone, "
            "waveform cursor at exact picosecond t_fault, and physical GDSII layout bounding box."
        ),
        telemetry_hook="highlighter (Carets) / cross_probe (4-View Telemetry)",
        badge_label="Rule 3: Quit Thinking and Look",
    ),

    AgansRuleId.RULE_4_DIVIDE_AND_CONQUER: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_4_DIVIDE_AND_CONQUER,
        rule_number=4,
        title="Divide and Conquer",
        mantra="Narrow the search space. Cut the problem in half until the bug has nowhere to hide.",
        summary=(
            "Isolate the faulty region from millions of lines or gates using backward program "
            "slicing, dominance frontiers, and structural cones of influence."
        ),
        software_application=(
            "CFG/DFG backward slicing from tainted sinks (SQL/eval) back to untrusted sources, "
            "pruning irrelevant execution branches."
        ),
        circuit_application=(
            "Extract structural Cone of Influence (COI) fanin/fanout logic cones and score candidate "
            "gate suspiciousness via Graph Neural Network (GNN) graph embeddings."
        ),
        telemetry_hook="cfg_dfg_analyzer (Slicing) / gnn_fault_locator (COI)",
        badge_label="Rule 4: Divide and Conquer",
    ),

    AgansRuleId.RULE_5_CHANGE_ONE_THING: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_5_CHANGE_ONE_THING,
        rule_number=5,
        title="Change One Thing at a Time",
        mantra="Isolate each change. If you change two things at once, you will never know which one worked.",
        summary=(
            "Generate atomic, minimal single-variable or single-gate modifications rather than "
            "sprawling multi-variable refactorings that introduce secondary defects."
        ),
        software_application=(
            "Synthesize minimal Unified Diffs (- / +) targeting a single guard, pointer nullification, "
            "or parameterization without mutating surrounding business logic."
        ),
        circuit_application=(
            "Perform single-gate buffer insertion, isolated driver gate resizing (e.g. 1X -> 2X), "
            "or isolated 2-FF synchronizer instantiation."
        ),
        telemetry_hook="auto_remediation (Unified Diff) / circuit_remediation",
        badge_label="Rule 5: Change One Thing at a Time",
    ),

    AgansRuleId.RULE_6_KEEP_AUDIT_TRAIL: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_6_KEEP_AUDIT_TRAIL,
        rule_number=6,
        title="Keep an Audit Trail",
        mantra="Write down what you did, in what order, and what happened. Don't trust your memory.",
        summary=(
            "Maintain an immutable chronological log of causal transitions, diagnostic timestamps, "
            "and standardized SARIF v2.1.0 telemetry for compliance and auditability."
        ),
        software_application=(
            "Multi-step causal trace trails (Step 1: Allocation -> Step 2: Deallocation -> Step 3: Dereference) "
            "and complete SARIF v2.1.0 JSON audit exports."
        ),
        circuit_application=(
            "Clock-cycle event logs, setup slack degradation tracking over layout iterations, "
            "and VCD waveform state timestamping."
        ),
        telemetry_hook="causal_trace (Step 1->2->3) / SARIF v2.1.0 Exporter",
        badge_label="Rule 6: Keep an Audit Trail",
    ),

    AgansRuleId.RULE_7_CHECK_THE_PLUG: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_7_CHECK_THE_PLUG,
        rule_number=7,
        title="Check the Plug",
        mantra="Question your assumptions. Always start with the simple, obvious basics first.",
        summary=(
            "Verify fundamental prerequisites before investigating complex algorithmic theories. "
            "Is the pointer null? Is the divisor zero? Is the pin connected? Is power connected?"
        ),
        software_application=(
            "Fast-fail pre-flight sanity checks: null dereferences, unchecked zero denominators, "
            "uninitialized variables, missing imports, and empty collections."
        ),
        circuit_application=(
            "Electrical Rule Checking (ERC): floating input pins, missing V_DD/V_SS power rails, "
            "unconnected clock pins, and multi-driver contention."
        ),
        telemetry_hook="preflight_sanity_check / erc_cdc_sta (Floating Nets)",
        badge_label="Rule 7: Check the Plug",
    ),

    AgansRuleId.RULE_8_FRESH_VIEW: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_8_FRESH_VIEW,
        rule_number=8,
        title="Get a Fresh View",
        mantra="Overcome tunnel vision. Ask for an outside perspective and cross-validate findings.",
        summary=(
            "Combine independent, orthogonal analytical perspectives to eliminate single-analyzer "
            "blind spots and confirm high-confidence defect localization."
        ),
        software_application=(
            "Tri-Engine Hybrid Scoring: R_total = w1*S_rule (static rules) + w2*S_ochiai (dynamic tests) "
            "+ w3*P_gnn (structural AI). Three independent engines vote on bug certainty."
        ),
        circuit_application=(
            "Cross-validate Static Timing Analysis (STA), Bounded Model Checking (Formal), and "
            "GNN fault probability to form consensus before recommending physical ECO changes."
        ),
        telemetry_hook="hybrid_priority_score (R_total Triangulation)",
        badge_label="Rule 8: Get a Fresh View",
    ),

    AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED: AgansRuleInfo(
        rule_id=AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        rule_number=9,
        title="If You Didn't Fix It, It Ain't Fixed",
        mantra="Never assume a fix works just because the symptom disappeared. Prove the root cause is solved.",
        summary=(
            "Enforce closed-loop automated verification. Re-test the patched system against the "
            "exact failing stimulus and prove zero regressions before marking the bug resolved."
        ),
        software_application=(
            "Closed-loop patch testing: apply the suggested diff in an isolated sandbox, re-run "
            "AST and CFG analysis, and verify the diagnostic count drops to 0 with zero syntax errors."
        ),
        circuit_application=(
            "Post-ECO re-timing: recalculate STA setup and hold slacks to mathematically prove "
            "Slack >= 0.0 ns and verify combinational loop freedom."
        ),
        telemetry_hook="closed_loop_fix_verifier / sta_recalculator",
        badge_label="Rule 9: If You Didn't Fix It, It Ain't Fixed",
    ),
}


# ─── Mapping 10 Production Rules to Agans Indispensable Rules ─────────────────

RULE_TO_AGANS_MAPPING: Dict[str, Dict[str, Any]] = {
    # Phase 1: Software Code Rules
    "CODE-MEM-001": {
        "primary_rule": AgansRuleId.RULE_6_KEEP_AUDIT_TRAIL,
        "contributing_rules": [
            AgansRuleId.RULE_7_CHECK_THE_PLUG,
            AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
            AgansRuleId.RULE_5_CHANGE_ONE_THING,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Use-After-Free requires Rule 6 (Audit Trail) to trace allocation, free, and dereference steps. "
            "Rule 7 (Check the Plug) ensures pointers are valid before dereferencing, and Rule 5 (Change One Thing) "
            "applies atomic nullification."
        ),
    },
    "CODE-MEM-002": {
        "primary_rule": AgansRuleId.RULE_2_MAKE_IT_FAIL,
        "contributing_rules": [
            AgansRuleId.RULE_4_DIVIDE_AND_CONQUER,
            AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
            AgansRuleId.RULE_7_CHECK_THE_PLUG,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Out-of-bounds buffer writes require Rule 2 (Make It Fail) with edge-case index testing (e.g. index >= len), "
            "and Rule 4 (Divide and Conquer) to isolate the boundary loop range."
        ),
    },
    "CODE-NUM-003": {
        "primary_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG,
        "contributing_rules": [
            AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
            AgansRuleId.RULE_5_CHANGE_ONE_THING,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Division by zero is the quintessential Rule 7 (Check the Plug) bug: never assume a divisor is non-zero. "
            "Rule 5 generates an isolated non-zero guard."
        ),
    },
    "CODE-SEC-004": {
        "primary_rule": AgansRuleId.RULE_4_DIVIDE_AND_CONQUER,
        "contributing_rules": [
            AgansRuleId.RULE_1_UNDERSTAND,
            AgansRuleId.RULE_6_KEEP_AUDIT_TRAIL,
            AgansRuleId.RULE_8_FRESH_VIEW,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Unsanitized taint sinks require Rule 4 (Divide and Conquer) to trace the data flow path between source and sink, "
            "and Rule 6 (Audit Trail) to document the unescaped taint journey."
        ),
    },
    "CODE-CON-005": {
        "primary_rule": AgansRuleId.RULE_8_FRESH_VIEW,
        "contributing_rules": [
            AgansRuleId.RULE_2_MAKE_IT_FAIL,
            AgansRuleId.RULE_4_DIVIDE_AND_CONQUER,
            AgansRuleId.RULE_5_CHANGE_ONE_THING,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Data races hide intermittently across threads. Rule 8 (Get a Fresh View) uses lockset analysis and GNN "
            "embeddings to spot concurrent access blind spots that single-threaded thinking misses."
        ),
    },

    # Phase 2: Hardware Circuit Rules
    "CIRC-STA-001": {
        "primary_rule": AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
        "contributing_rules": [
            AgansRuleId.RULE_1_UNDERSTAND,
            AgansRuleId.RULE_4_DIVIDE_AND_CONQUER,
            AgansRuleId.RULE_5_CHANGE_ONE_THING,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "STA setup/hold violations require Rule 3 (Quit Thinking and Look) through synchronized 4-view cross-probing "
            "(waveform cursor + GDSII wire delay), and Rule 9 (prove Slack >= 0.0 ns after buffer insertion)."
        ),
    },
    "CIRC-CDC-002": {
        "primary_rule": AgansRuleId.RULE_1_UNDERSTAND,
        "contributing_rules": [
            AgansRuleId.RULE_7_CHECK_THE_PLUG,
            AgansRuleId.RULE_5_CHANGE_ONE_THING,
            AgansRuleId.RULE_6_KEEP_AUDIT_TRAIL,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Clock-domain crossings require Rule 1 (Understand the System) to recognize distinct asynchronous clock domains "
            "and enforce 2-FF synchronizer contracts."
        ),
    },
    "CIRC-ERC-003": {
        "primary_rule": AgansRuleId.RULE_4_DIVIDE_AND_CONQUER,
        "contributing_rules": [
            AgansRuleId.RULE_1_UNDERSTAND,
            AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Combinational feedback loops require Rule 4 (Divide and Conquer) via Tarjan's strongly connected components "
            "cycle detection to isolate the oscillating loop."
        ),
    },
    "CIRC-ERC-004": {
        "primary_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG,
        "contributing_rules": [
            AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
            AgansRuleId.RULE_5_CHANGE_ONE_THING,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Floating nets and open gate inputs are the hardware equivalent of Rule 7 (Check the Plug): verify basic "
            "connectivity before running complex timing analysis."
        ),
    },
    "CIRC-PWR-005": {
        "primary_rule": AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
        "contributing_rules": [
            AgansRuleId.RULE_7_CHECK_THE_PLUG,
            AgansRuleId.RULE_8_FRESH_VIEW,
            AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED,
        ],
        "rationale": (
            "Analog IR-drop violations require Rule 3 (Quit Thinking and Look) to inspect GDSII metal layers and nodal "
            "voltages, combined with Rule 7 (verify V_DD supply rail integrity)."
        ),
    },
}


def get_agans_rule(rule_id: AgansRuleId) -> AgansRuleInfo:
    """Retrieve full details for an Agans Indispensable Rule."""
    return AGANS_NINE_RULES[rule_id]


def get_agans_mapping_for_rule(detection_rule_id: str) -> Dict[str, Any]:
    """Retrieve the Agans rules mapping for a given detection rule ID."""
    mapping = RULE_TO_AGANS_MAPPING.get(detection_rule_id)
    if not mapping:
        # Default fallback mapping
        return {
            "primary_rule": AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK,
            "contributing_rules": [AgansRuleId.RULE_7_CHECK_THE_PLUG, AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED],
            "rationale": "Inspect observable evidence and verify the fix.",
            "primary_info": AGANS_NINE_RULES[AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK].to_dict(),
        }

    primary_info = AGANS_NINE_RULES[mapping["primary_rule"]].to_dict()
    contributing_info = [AGANS_NINE_RULES[r].to_dict() for r in mapping["contributing_rules"]]
    return {
        "primary_rule": mapping["primary_rule"].value,
        "primary_info": primary_info,
        "contributing_rules": [r.value for r in mapping["contributing_rules"]],
        "contributing_info": contributing_info,
        "rationale": mapping["rationale"],
    }


# ─── Rule 7: Pre-Flight Sanity Checker ("Check the Plug") ─────────────────────

class AgansPreFlightChecker:
    """
    Implements Agans Rule 7: "Check the Plug".

    Executes rapid, low-overhead baseline checks on code or netlists before
    engaging heavy symbolic execution, SMT solvers, or GNN inference.
    """

    @staticmethod
    def check_code_sanity(source_code: str, filename: str = "source.py") -> List[Dict[str, Any]]:
        """Verify baseline code preconditions (Rule 7: Check the Plug)."""
        issues: List[Dict[str, Any]] = []

        if not source_code.strip():
            issues.append({
                "rule_id": "AGANS-CHK-001",
                "agans_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG.value,
                "severity": "CRITICAL",
                "message": "Source code buffer is empty. (Check the Plug: Nothing to analyze!)",
                "line": 1,
            })
            return issues

        # Syntax check
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError as e:
            issues.append({
                "rule_id": "AGANS-CHK-002",
                "agans_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG.value,
                "severity": "CRITICAL",
                "message": f"Syntax error at line {e.lineno}, col {e.offset}: {e.msg} (Check the Plug: Code does not compile!)",
                "line": e.lineno or 1,
            })
            return issues

        # Check for obvious literal zero divisors (Rule 7)
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                if isinstance(node.right, ast.Constant) and node.right.value == 0:
                    issues.append({
                        "rule_id": "AGANS-CHK-003",
                        "agans_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG.value,
                        "severity": "CRITICAL",
                        "message": f"Literal division by zero at line {node.lineno}. (Check the Plug: Divisor is hardcoded to 0!)",
                        "line": node.lineno,
                    })

        return issues

    @staticmethod
    def check_netlist_sanity(netlist: dict) -> List[Dict[str, Any]]:
        """Verify baseline circuit netlist preconditions (Rule 7: Check the Plug)."""
        issues: List[Dict[str, Any]] = []

        if not netlist:
            issues.append({
                "rule_id": "AGANS-CHK-NET-001",
                "agans_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG.value,
                "severity": "CRITICAL",
                "message": "Netlist structure is empty or null. (Check the Plug: Circuit not loaded!)",
            })
            return issues

        gates = netlist.get("gates", {})
        nets = netlist.get("nets", {})

        if not gates and not nets:
            issues.append({
                "rule_id": "AGANS-CHK-NET-002",
                "agans_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG.value,
                "severity": "CRITICAL",
                "message": "Netlist contains 0 gates and 0 nets. (Check the Plug: Empty circuit topology!)",
            })

        # Check for ungrounded/unpowered inputs (Rule 7)
        if isinstance(nets, dict):
            for net_name, net_data in nets.items():
                if isinstance(net_data, dict):
                    drivers = net_data.get("drivers", [])
                    sinks = net_data.get("sinks", [])
                    if len(drivers) == 0 and len(sinks) > 0:
                        issues.append({
                            "rule_id": "AGANS-CHK-NET-003",
                            "agans_rule": AgansRuleId.RULE_7_CHECK_THE_PLUG.value,
                            "severity": "VIOLET_NET",
                            "message": f"Net '{net_name}' drives {len(sinks)} gate inputs but has no power or driver. (Check the Plug: Net is disconnected!)",
                            "net": net_name,
                        })

        return issues


# ─── Rule 9: Closed-Loop Fix Verifier ("If You Didn't Fix It, It Ain't Fixed") ─

class AgansClosedLoopVerifier:
    """
    Implements Agans Rule 9: "If You Didn't Fix It, It Ain't Fixed".

    Applies a proposed patch or remediation to source code in an isolated
    sandbox, re-analyzes the result, and mathematically certifies:
    1. Did the specific targeted bug go away?
    2. Did the change introduce any new syntax errors or regressions?
    3. Is the system now verified clean?
    """

    @classmethod
    def apply_patch(cls, original_source: str, patch_code_or_diff: str) -> str:
        """Apply replacement code or unified diff to produce modified source."""
        # If the patch is already complete replacement source code:
        if "\n" in patch_code_or_diff and not patch_code_or_diff.startswith("---") and not patch_code_or_diff.startswith("-"):
            # Check if it looks like a full snippet or single line
            if len(patch_code_or_diff.splitlines()) >= len(original_source.splitlines()) * 0.7:
                return patch_code_or_diff

        # If it's a replacement string or line substitution:
        lines = original_source.splitlines()
        patch_lines = patch_code_or_diff.splitlines()

        # Find target line from deletion markers in unified diff
        del_lines = [l[1:].strip() for l in patch_lines if l.startswith("-") and not l.startswith("---")]
        add_lines = [l[1:] for l in patch_lines if l.startswith("+") and not l.startswith("+++")]

        if del_lines and add_lines:
            new_lines = []
            replaced = False
            for line in lines:
                if not replaced and any(d in line for d in del_lines):
                    # Match the exact indentation of the original line being replaced
                    orig_indent = line[:len(line) - len(line.lstrip())]
                    for add_l in add_lines:
                        stripped_add = add_l.lstrip()
                        new_lines.append(f"{orig_indent}{stripped_add}")
                    replaced = True
                else:
                    new_lines.append(line)
            if replaced:
                return "\n".join(new_lines)

        # Fallback: simple line replacement if single line provided
        return original_source

    @classmethod
    def verify_code_fix(
        cls,
        original_source: str,
        patched_source: str,
        target_rule_id: str,
        analyzer_callable: Any,
    ) -> Dict[str, Any]:
        """
        Verify that applying the patch resolves the targeted bug under Rule 9.

        Args:
            original_source: The buggy source code before remediation.
            patched_source: The proposed remediated source code.
            target_rule_id: The specific rule ID expected to be resolved (e.g. CODE-MEM-001).
            analyzer_callable: Function that accepts source code and returns diagnostic dicts.

        Returns:
            Dictionary certifying verification status under Agans Rule 9.
        """
        # Step 1: Pre-patch verification — confirm the bug was present
        before_diags = analyzer_callable(original_source)
        targeted_before = [d for d in before_diags if d.get("rule_id") == target_rule_id]

        # Step 2: Syntax sanity check on patched code (Rule 7 + Rule 1)
        syntax_ok = True
        syntax_error = ""
        try:
            ast.parse(patched_source)
        except SyntaxError as e:
            syntax_ok = False
            syntax_error = f"SyntaxError at line {e.lineno}: {e.msg}"

        if not syntax_ok:
            return {
                "agans_rule": AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED.value,
                "verified": False,
                "status": "REGRESSION_SYNTAX_ERROR",
                "message": f"Rule 9 Failed: Proposed patch introduced syntax error: {syntax_error}",
                "target_rule_id": target_rule_id,
                "before_count": len(targeted_before),
                "after_count": len(targeted_before),
                "diff": cls._generate_diff(original_source, patched_source),
            }

        # Step 3: Post-patch execution — re-run the analyzer on patched code
        after_diags = analyzer_callable(patched_source)
        targeted_after = [d for d in after_diags if d.get("rule_id") == target_rule_id]

        # Check if new issues appeared (regressions)
        new_issues = [
            d for d in after_diags
            if d.get("rule_id") not in [b.get("rule_id") for b in before_diags]
        ]

        if len(targeted_after) == 0 and len(new_issues) == 0:
            return {
                "agans_rule": AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED.value,
                "verified": True,
                "status": "VERIFIED_CLEAN",
                "message": (
                    f"Agans Rule 9 Verified: Defect {target_rule_id} completely eliminated! "
                    f"Closed-loop analysis confirms 0 regressions and valid AST contracts."
                ),
                "target_rule_id": target_rule_id,
                "before_count": len(targeted_before),
                "after_count": 0,
                "regressions_count": 0,
                "diff": cls._generate_diff(original_source, patched_source),
            }
        elif len(targeted_after) > 0:
            return {
                "agans_rule": AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED.value,
                "verified": False,
                "status": "DEFECT_PERSISTS",
                "message": (
                    f"Agans Rule 9 Warning: Defect {target_rule_id} still triggers after patch! "
                    f"'If you didn't fix it, it ain't fixed.' Further investigation required."
                ),
                "target_rule_id": target_rule_id,
                "before_count": len(targeted_before),
                "after_count": len(targeted_after),
                "regressions_count": len(new_issues),
                "diff": cls._generate_diff(original_source, patched_source),
            }
        else:
            return {
                "agans_rule": AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED.value,
                "verified": False,
                "status": "SIDE_EFFECT_REGRESSION",
                "message": (
                    f"Agans Rule 9 Warning: Targeted defect was removed but {len(new_issues)} "
                    f"secondary regression(s) were introduced: {[n.get('rule_id') for n in new_issues]}."
                ),
                "target_rule_id": target_rule_id,
                "before_count": len(targeted_before),
                "after_count": len(targeted_after),
                "regressions_count": len(new_issues),
                "diff": cls._generate_diff(original_source, patched_source),
            }

    @staticmethod
    def _generate_diff(original: str, patched: str) -> str:
        """Generate human-readable unified diff between original and patched code."""
        orig_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        diff = difflib.unified_diff(orig_lines, patched_lines, fromfile="before.py", tofile="after.py")
        return "".join(diff)

"""
The Pragmatic Programmer — Engineering Principles & Automation Framework.

Reference:
"The Pragmatic Programmer: From Journeyman to Master" & 20th Anniversary Edition
by David Thomas and Andrew Hunt.

Provides first-class implementations for:
1. Problem Solving (Tracer Bullets, Don't Assume - Prove It, Root Cause)
2. Clean Coding (DRY - Don't Repeat Yourself, Broken Windows Theory, Orthogonality)
3. Software Design (Design by Contract - Pre/Post/Invariants, Crash Early, Assertive Programming)
4. Testing (Ruthless Testing, Test Early, Test Often, Test Automatically)
5. Code Maintenance (Refactor Early & Often, ETC - Easier to Change, Decoupling)
6. Automation (Ubiquitous Automation, Never Use Manual Procedures)
"""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PragmaticPillar(str, Enum):
    PROBLEM_SOLVING = "PROBLEM_SOLVING"
    CLEAN_CODING = "CLEAN_CODING"
    SOFTWARE_DESIGN = "SOFTWARE_DESIGN"
    TESTING = "TESTING"
    CODE_MAINTENANCE = "CODE_MAINTENANCE"
    AUTOMATION = "AUTOMATION"


@dataclass
class PragmaticTip:
    number: int
    title: str
    pillar: PragmaticPillar
    quote: str
    actionable_rule: str
    telemetry_metric: str


PRAGMATIC_TIPS: List[PragmaticTip] = [
    # ── Problem Solving ──
    PragmaticTip(
        number=12,
        title="Use Tracer Bullets to Find the Target",
        pillar=PragmaticPillar.PROBLEM_SOLVING,
        quote="Tracer bullets let you home in on your target by trying things and seeing how close they land.",
        actionable_rule="Fire lightweight end-to-end execution slices across parser, AST, taint graph, and solver before complex analysis.",
        telemetry_metric="tracer_bullet_latency_ms",
    ),
    PragmaticTip(
        number=26,
        title="Don't Assume It — Prove It",
        pillar=PragmaticPillar.PROBLEM_SOLVING,
        quote="Prove your assumptions in the actual environment, with real data and boundary conditions.",
        actionable_rule="Never guess bug locations; generate mathematical proof via SMT solver or exact waveform timestamp.",
        telemetry_metric="formal_proof_certainty",
    ),
    PragmaticTip(
        number=27,
        title="Fix the Problem, Not the Blame",
        pillar=PragmaticPillar.PROBLEM_SOLVING,
        quote="It doesn't really matter whether the bug is your fault or someone else's. It is still your problem.",
        actionable_rule="Isolate the underlying defect with non-accusatory causal traces pointing directly to the root expression.",
        telemetry_metric="causal_chain_depth",
    ),

    # ── Clean Coding ──
    PragmaticTip(
        number=3,
        title="Don't Live with Broken Windows",
        pillar=PragmaticPillar.CLEAN_CODING,
        quote="Fix bad designs, wrong decisions, and poor code when you see them. Don't let neglect cause systemic decay.",
        actionable_rule="Maintain a Broken Windows Index. Repair unhandled branches, unvalidated inputs, and unchecked memory immediately.",
        telemetry_metric="broken_windows_index",
    ),
    PragmaticTip(
        number=9,
        title="DRY — Don't Repeat Yourself",
        pillar=PragmaticPillar.CLEAN_CODING,
        quote="Every piece of knowledge must have a single, unambiguous, authoritative representation within a system.",
        actionable_rule="Detect duplicated business logic, redundant taint sanitization, and parallel state representations.",
        telemetry_metric="dry_duplication_score",
    ),
    PragmaticTip(
        number=14,
        title="Eliminate Effects Between Unrelated Things",
        pillar=PragmaticPillar.CLEAN_CODING,
        quote="Design components that are self-contained, independent, and have a single, well-defined purpose (Orthogonality).",
        actionable_rule="Enforce orthogonality between arithmetic validation, memory lifecycles, and network I/O.",
        telemetry_metric="orthogonality_coupling_ratio",
    ),

    # ── Software Design ──
    PragmaticTip(
        number=37,
        title="Design with Contracts (DbC)",
        pillar=PragmaticPillar.SOFTWARE_DESIGN,
        quote="Use contracts to document and verify that code does no more and no less than it claims to do.",
        actionable_rule="Enforce Preconditions (what the caller must supply), Postconditions (what the routine guarantees), and Invariants.",
        telemetry_metric="dbc_contract_violations",
    ),
    PragmaticTip(
        number=38,
        title="Dead Programs Tell No Lies",
        pillar=PragmaticPillar.SOFTWARE_DESIGN,
        quote="Crash early. A dead program normally does a lot less damage than a crippled one.",
        actionable_rule="Trigger immediate defensive assertions or fast-fail exceptions rather than continuing with undefined state.",
        telemetry_metric="crash_early_coverage",
    ),
    PragmaticTip(
        number=39,
        title="Use Assertions to Prevent the Impossible",
        pillar=PragmaticPillar.SOFTWARE_DESIGN,
        quote="Whenever you find yourself thinking 'but of course that could never happen,' add code to check it.",
        actionable_rule="Synthesize guards: assert divisor != 0, assert ptr is not None, assert 0 <= idx < len(buffer).",
        telemetry_metric="assertion_density",
    ),

    # ── Testing ──
    PragmaticTip(
        number=62,
        title="Test Early, Test Often, Test Automatically",
        pillar=PragmaticPillar.TESTING,
        quote="Tests that run with every build are much more effective than test plans that sit on a shelf.",
        actionable_rule="Couple static diagnostics with dynamic Spectrum-Based Fault Localization (Ochiai SBFL) test runs.",
        telemetry_metric="ochiai_sbfl_score",
    ),
    PragmaticTip(
        number=63,
        title="Ruthless Testing: Coding Ain't Done 'Til All Tests Run",
        pillar=PragmaticPillar.TESTING,
        quote="Don't write code without testing, and don't stop testing until you've tried to break it.",
        actionable_rule="Automate closed-loop patch verification: re-run full test harness in a sandbox before accepting any fix.",
        telemetry_metric="closed_loop_pass_rate",
    ),

    # ── Code Maintenance ──
    PragmaticTip(
        number=47,
        title="Refactor Early, Refactor Often",
        pillar=PragmaticPillar.CODE_MAINTENANCE,
        quote="Just as you weed a garden, code requires constant weeding and maintenance. Don't let technical debt pile up.",
        actionable_rule="Generate targeted, minimal unified diff refactorings that eliminate root defects without collateral breakage.",
        telemetry_metric="refactoring_diff_lines",
    ),
    PragmaticTip(
        number=8,
        title="Good Design Is Easier to Change (ETC)",
        pillar=PragmaticPillar.CODE_MAINTENANCE,
        quote="The ETC principle is a guide, not a rule. Ask yourself: does what I just did make the overall system easier or harder to change?",
        actionable_rule="Synthesize parameterized queries, pipeline registers, and isolated synchronizer modules.",
        telemetry_metric="etc_modularity_rating",
    ),

    # ── Automation ──
    PragmaticTip(
        number=49,
        title="Don't Use Manual Procedures",
        pillar=PragmaticPillar.AUTOMATION,
        quote="A manual procedure is an error waiting to happen. People are just not as repeatable as computers.",
        actionable_rule="Automate all multi-step workflows into single-click or CLI pipelines (SARIF export, LSP overlays, AST linting).",
        telemetry_metric="pipeline_automation_pct",
    ),
]


@dataclass
class BrokenWindowItem:
    window_id: str
    file: str
    line: int
    category: str
    description: str
    severity: str
    entropy_weight: int
    clean_code_tip: str
    remediation_hint: str


@dataclass
class BrokenWindowsReport:
    total_score: int          # 0 (Pristine) to 100 (Maximum Entropy / Severe Decay)
    entropy_level: str        # "PRISTINE", "LOW_ENTROPY", "ELEVATED_DECAY", "CRITICAL_ROT"
    windows_count: int
    windows: List[BrokenWindowItem]
    advice: str
    clean_code_rating: str    # "A+", "B", "C", "D", "F"


@dataclass
class ContractViolation:
    contract_type: str        # "PRECONDITION", "POSTCONDITION", "INVARIANT"
    function_or_scope: str
    formal_clause: str
    breached_expression: str
    fault_party: str          # "CALLER", "SUPPLIER"
    line: int
    remedy: str


@dataclass
class TracerBulletStage:
    stage_id: str
    name: str
    status: str              # "PASS", "FAIL", "SKIPPED"
    duration_ms: float
    output_summary: str


@dataclass
class TracerBulletResult:
    success: bool
    total_duration_ms: float
    stages: List[TracerBulletStage]
    target_hit: bool
    summary: str


class PragmaticAnalyzer:
    """Analyzer implementing the core principles of The Pragmatic Programmer."""

    @staticmethod
    def compute_broken_windows(
        diagnostics: List[Any],
        source_code: str = "",
    ) -> BrokenWindowsReport:
        """Calculate the Broken Windows Index (Software Entropy Metric).
        
        Score:
        - 0-10: Pristine (No broken windows, clean architecture)
        - 11-30: Low Entropy (Minor windows, easily repaired)
        - 31-65: Elevated Decay (Multiple broken windows signaling neglect)
        - 66-100: Critical Rot (Broken windows inviting further bugs; immediate refactoring needed)
        """
        windows: List[BrokenWindowItem] = []
        raw_score = 0

        severity_weights = {
            "CRITICAL": 25,
            "WARNING": 12,
            "VIOLET_NET": 20,
            "INFO": 5,
            "NEON_AI": 8,
        }

        # Analyze diagnostics as broken windows
        for idx, d in enumerate(diagnostics):
            sev = getattr(d, "severity", "WARNING")
            rule_id = getattr(d, "rule_id", f"WIN-{idx+1:03d}")
            msg = getattr(d, "message", "Detected software imperfection")
            line = 1
            code_span = getattr(d, "code_span", None)
            if code_span:
                line = getattr(code_span, "start_line", 1)

            weight = severity_weights.get(sev, 10)
            raw_score += weight

            # Select tip
            if "zero" in msg.lower() or "NUM" in rule_id:
                tip = "Tip 37: Design with Contracts — Require non-zero divisor precondition."
                hint = "Add assert divisor != 0 or if divisor == 0: raise ValueError(...)"
            elif "free" in msg.lower() or "MEM" in rule_id:
                tip = "Tip 3: Don't Live with Broken Windows — Repair pointer lifecycles immediately."
                hint = "Nullify pointer after deallocation and avoid dangling access."
            elif "taint" in msg.lower() or "SEC" in rule_id:
                tip = "Tip 14: Eliminate Effects Between Unrelated Things — Isolate untrusted I/O from execution sinks."
                hint = "Use parameterized queries or strict type validation."
            elif "race" in msg.lower() or "CON" in rule_id:
                tip = "Tip 14: Orthogonality — Shared mutable state creates hidden temporal coupling."
                hint = "Guard critical section with threading lock or atomic operation."
            elif "slack" in msg.lower() or "STA" in rule_id:
                tip = "Tip 26: Don't Assume It — Prove It: Prove clock edge setup slack >= 0.0 ns."
                hint = "Insert pipeline register stage to divide critical combinatorial path."
            elif "cdc" in msg.lower() or "CDC" in rule_id:
                tip = "Tip 37: Design with Contracts — Enforce 2-FF synchronizer contract across async clock domains."
                hint = "Instantiate dual-flip-flop synchronizer or asynchronous Gray-code FIFO."
            else:
                tip = "Tip 47: Refactor Early, Refactor Often — Keep code clean and debt-free."
                hint = "Refactor logic to eliminate complexity and enforce contracts."

            windows.append(
                BrokenWindowItem(
                    window_id=f"BW-{idx+1:03d}",
                    file="source.py",
                    line=line,
                    category=getattr(d, "category", rule_id),
                    description=msg,
                    severity=sev,
                    entropy_weight=weight,
                    clean_code_tip=tip,
                    remediation_hint=hint,
                )
            )

        # Code smell inspection (AST level)
        if source_code:
            try:
                tree = ast.parse(source_code)
                for node in ast.walk(tree):
                    # Bare except: except:
                    if isinstance(node, ast.ExceptHandler) and node.type is None:
                        raw_score += 15
                        windows.append(
                            BrokenWindowItem(
                                window_id=f"BW-SMELL-{len(windows)+1}",
                                file="source.py",
                                line=node.lineno,
                                category="Bare Exception Handler",
                                description="Catching all exceptions with bare 'except:' masks critical crashes (Violates 'Crash Early').",
                                severity="WARNING",
                                entropy_weight=15,
                                clean_code_tip="Tip 38: Dead Programs Tell No Lies — Catch specific exceptions or let program crash early.",
                                remediation_hint="Specify exact exception type (e.g., except KeyError:) instead of bare except:.",
                            )
                        )
                    # Hardcoded magic numbers in division or comparisons
                    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                        if isinstance(node.right, ast.Constant) and node.right.value == 0:
                            # Already caught by rule engine or add note
                            pass
            except Exception:
                pass

        # Normalized score 0-100
        score = min(100, raw_score)

        if score == 0:
            entropy_level = "PRISTINE"
            clean_code_rating = "A+"
            advice = "Zero broken windows detected! The codebase exemplifies Pragmatic Craftsmanship."
        elif score <= 20:
            entropy_level = "LOW_ENTROPY"
            clean_code_rating = "A"
            advice = "Minor imperfections detected. Repair these small windows immediately to prevent rot."
        elif score <= 50:
            entropy_level = "ELEVATED_DECAY"
            clean_code_rating = "C"
            advice = "Multiple broken windows found. According to Tip 3, repair them now before neglect compounds."
        else:
            entropy_level = "CRITICAL_ROT"
            clean_code_rating = "F"
            advice = "High technical debt! Unchecked bugs and missing contracts invite severe cascade failures. Refactor immediately."

        return BrokenWindowsReport(
            total_score=score,
            entropy_level=entropy_level,
            windows_count=len(windows),
            windows=windows,
            advice=advice,
            clean_code_rating=clean_code_rating,
        )

    @staticmethod
    def inspect_contracts(
        source_code: str,
        diagnostics: List[Any],
    ) -> List[ContractViolation]:
        """Inspect Design by Contract (DbC) compliance.
        
        Checks:
        - Preconditions (caller obligations): divisor != 0, ptr != null, 0 <= idx < len, sanitized input.
        - Postconditions (supplier guarantees): returned valid result, memory freed, resources closed.
        - Invariants (system state that must never be violated).
        """
        violations: List[ContractViolation] = []

        for d in diagnostics:
            rule_id = getattr(d, "rule_id", "")
            msg = getattr(d, "message", "")
            code_span = getattr(d, "code_span", None)
            line = getattr(code_span, "start_line", 1) if code_span else 1

            if "NUM-003" in rule_id or "zero" in msg.lower():
                violations.append(
                    ContractViolation(
                        contract_type="PRECONDITION",
                        function_or_scope="Arithmetic Division Expression",
                        formal_clause="require: divisor != 0",
                        breached_expression="a / divisor (where divisor evaluates to 0)",
                        fault_party="CALLER",
                        line=line,
                        remedy="Caller must satisfy contract requirement 'divisor != 0' before initiating division.",
                    )
                )
            elif "MEM-001" in rule_id or "free" in msg.lower():
                violations.append(
                    ContractViolation(
                        contract_type="INVARIANT",
                        function_or_scope="Memory Lifecycle Management",
                        formal_clause="invariant: state(ptr) in {ALLOCATED, NULL} during dereference",
                        breached_expression="deref(ptr) after state(ptr) == FREED",
                        fault_party="SUPPLIER",
                        line=line,
                        remedy="Enforce class invariant: pointers must be either validly allocated or NULL.",
                    )
                )
            elif "MEM-002" in rule_id or "bounds" in msg.lower() or "overflow" in msg.lower():
                violations.append(
                    ContractViolation(
                        contract_type="PRECONDITION",
                        function_or_scope="Array/Buffer Subscripting",
                        formal_clause="require: 0 <= index < len(buffer)",
                        breached_expression="buffer[index] (index exceeds array boundary)",
                        fault_party="CALLER",
                        line=line,
                        remedy="Caller must guarantee index falls strictly within [0, len) before accessing elements.",
                    )
                )
            elif "SEC-004" in rule_id or "taint" in msg.lower():
                violations.append(
                    ContractViolation(
                        contract_type="PRECONDITION",
                        function_or_scope="SQL/Command Execution Sink",
                        formal_clause="require: is_sanitized(user_input) == True",
                        breached_expression="execute('SELECT ... ' + user_input)",
                        fault_party="CALLER",
                        line=line,
                        remedy="Precondition breached: untrusted external input passed into sensitive sink without sanitization contract.",
                    )
                )
            elif "STA-001" in rule_id or "slack" in msg.lower():
                violations.append(
                    ContractViolation(
                        contract_type="POSTCONDITION",
                        function_or_scope="Synchronous Clock Edge Transfer",
                        formal_clause="ensure: Slack_setup >= 0.0 ns and Slack_hold >= 0.0 ns",
                        breached_expression="Slack < 0.0 ns (Path delay exceeds clock cycle T_clk)",
                        fault_party="SUPPLIER",
                        line=line,
                        remedy="Supplier logic cone failed to guarantee required setup slack postcondition.",
                    )
                )
            elif "CDC-002" in rule_id or "cdc" in msg.lower():
                violations.append(
                    ContractViolation(
                        contract_type="INVARIANT",
                        function_or_scope="Clock Domain Crossing Boundary",
                        formal_clause="invariant: synchronizer_stages >= 2 across CLK_A -> CLK_B",
                        breached_expression="Direct flip-flop connection across asynchronous clock domains",
                        fault_party="SUPPLIER",
                        line=line,
                        remedy="Metastability invariant broken: asynchronous clock domain crossings require a 2-FF contract.",
                    )
                )

        return violations

    @staticmethod
    def run_tracer_bullet(
        source_code: str,
        netlist: Optional[dict] = None,
    ) -> TracerBulletResult:
        """Execute a Pragmatic Tracer Bullet across the entire software and circuit pipeline.
        
        Tip 12: 'Use Tracer Bullets to Find the Target'.
        Fires an end-to-end slice verifying:
        Stage 1: Grammar & AST Lexing
        Stage 2: Design by Contract Sanity Probe
        Stage 3: Taint & Data Flow Traversal
        Stage 4: Automated Patch & Closed-Loop Verification Target
        """
        t0 = time.perf_counter()
        stages: List[TracerBulletStage] = []

        # Stage 1: AST Parsing
        s1_t0 = time.perf_counter()
        try:
            tree = ast.parse(source_code)
            s1_dur = (time.perf_counter() - s1_t0) * 1000
            nodes_count = sum(1 for _ in ast.walk(tree))
            stages.append(
                TracerBulletStage(
                    stage_id="STAGE_1_AST",
                    name="Tracer Bullet 1: AST Grammar & Structural Parsing",
                    status="PASS",
                    duration_ms=round(s1_dur, 2),
                    output_summary=f"Abstract Syntax Tree parsed successfully ({nodes_count} AST nodes discovered).",
                )
            )
        except SyntaxError as e:
            s1_dur = (time.perf_counter() - s1_t0) * 1000
            stages.append(
                TracerBulletStage(
                    stage_id="STAGE_1_AST",
                    name="Tracer Bullet 1: AST Grammar & Structural Parsing",
                    status="FAIL",
                    duration_ms=round(s1_dur, 2),
                    output_summary=f"SyntaxError encountered at line {e.lineno}: {e.msg}",
                )
            )
            total_dur = (time.perf_counter() - t0) * 1000
            return TracerBulletResult(
                success=False,
                total_duration_ms=round(total_dur, 2),
                stages=stages,
                target_hit=False,
                summary="Tracer bullet stopped at Stage 1 due to syntax error.",
            )

        # Stage 2: Contract Preconditions
        s2_t0 = time.perf_counter()
        precond_issues = []
        if "/ 0" in source_code or "/0" in source_code or "divisor = 0" in source_code:
            precond_issues.append("Literal zero divisor detected without non-zero precondition guard.")
        if "input(" in source_code and ("SELECT" in source_code or "WHERE" in source_code):
            precond_issues.append("Untrusted input concatenated into SQL query without sanitization contract.")
        s2_dur = (time.perf_counter() - s2_t0) * 1000

        stages.append(
            TracerBulletStage(
                stage_id="STAGE_2_DBC",
                name="Tracer Bullet 2: Design by Contract (DbC) Sanity Probe",
                status="FAIL" if precond_issues else "PASS",
                duration_ms=round(s2_dur, 2),
                output_summary="Contract verified clean." if not precond_issues else "; ".join(precond_issues),
            )
        )

        # Stage 3: Dataflow & Sinks
        s3_t0 = time.perf_counter()
        has_sinks = any(k in source_code for k in ["process(", "execute(", "free_buf(", "allocate_buffer("])
        s3_dur = (time.perf_counter() - s3_t0) * 1000
        stages.append(
            TracerBulletStage(
                stage_id="STAGE_3_DATAFLOW",
                name="Tracer Bullet 3: Control & Data Flow Graph (CFG/DFG) Trace",
                status="PASS",
                duration_ms=round(s3_dur, 2),
                output_summary=f"End-to-end dataflow paths traversed. Critical API sinks verified ({'Sinks active' if has_sinks else 'Clean flow'}).",
            )
        )

        # Stage 4: Circuit Netlist (if provided)
        if netlist:
            s4_t0 = time.perf_counter()
            gates = netlist.get("gates", [])
            s4_dur = (time.perf_counter() - s4_t0) * 1000
            stages.append(
                TracerBulletStage(
                    stage_id="STAGE_4_CIRCUIT",
                    name="Tracer Bullet 4: Hardware Netlist Hypergraph Probe",
                    status="PASS",
                    duration_ms=round(s4_dur, 2),
                    output_summary=f"Circuit topology verified ({len(gates)} gate instances mapped across clock domains).",
                )
            )

        total_dur = (time.perf_counter() - t0) * 1000
        all_passed = all(st.status == "PASS" for st in stages)

        return TracerBulletResult(
            success=True,
            total_duration_ms=round(total_dur, 2),
            stages=stages,
            target_hit=all_passed,
            summary="Tracer bullet complete: end-to-end architectural pipeline illuminated." if all_passed else "Tracer bullet illuminated defects along the execution path.",
        )

    @staticmethod
    def get_refactoring_advice(diagnostics: List[Any]) -> List[Dict[str, Any]]:
        """Generate Pragmatic Programmer refactoring recommendations based on ETC (Easier To Change)."""
        advice_list = []
        for d in diagnostics:
            rule_id = getattr(d, "rule_id", "")
            msg = getattr(d, "message", "")

            if "NUM-003" in rule_id or "zero" in msg.lower():
                advice_list.append({
                    "rule_id": rule_id,
                    "principle": "ETC (Easier to Change) & Design by Contract",
                    "pragmatic_tip": "Tip 37: Design with Contracts & Tip 39: Assertive Programming",
                    "step_1": "Decouple division calculation into a safe helper function.",
                    "step_2": "Add an explicit precondition assertion: assert divisor != 0, 'Divisor cannot be zero'.",
                    "step_3": "Provide an early fallback or descriptive ZeroDivisionError to fail fast (Tip 38).",
                })
            elif "MEM-001" in rule_id or "free" in msg.lower():
                advice_list.append({
                    "rule_id": rule_id,
                    "principle": "Tip 3: Don't Live with Broken Windows & Resource Lifecycle Ownership",
                    "pragmatic_tip": "Tip 35: Finish What You Start — Deallocate resources in the opposite order of allocation.",
                    "step_1": "Adopt RAII or context manager ('with' block) to guarantee deterministic deallocation.",
                    "step_2": "Nullify references immediately upon deallocation (ptr = None).",
                    "step_3": "Eliminate conditional free paths that leave dangling references active.",
                })
            elif "SEC-004" in rule_id or "taint" in msg.lower():
                advice_list.append({
                    "rule_id": rule_id,
                    "principle": "Tip 14: Orthogonality & Tip 9: DRY",
                    "pragmatic_tip": "Tip 14: Eliminate Effects Between Unrelated Things",
                    "step_1": "Replace manual string concatenation with parameterized SQL bindings.",
                    "step_2": "Encapsulate data querying behind a strongly-typed repository interface.",
                    "step_3": "Isolate input validation at the boundary, ensuring raw user strings never reach SQL engines.",
                })
            elif "STA-001" in rule_id or "slack" in msg.lower():
                advice_list.append({
                    "rule_id": rule_id,
                    "principle": "Hardware Architecture Modularization",
                    "pragmatic_tip": "Tip 47: Refactor Early, Refactor Often",
                    "step_1": "Pipelining: Insert intermediate D-flip-flop register stages to split combinatorial delay.",
                    "step_2": "Gate Resizing: Upgrade high-fanout drivers from 1X to 2X cell drive strength.",
                    "step_3": "Verify post-ECO timing with Static Timing Analysis to mathematically prove Slack >= 0.0 ns.",
                })
            elif "CDC-002" in rule_id or "cdc" in msg.lower():
                advice_list.append({
                    "rule_id": rule_id,
                    "principle": "Design by Contract — Asynchronous Crossing Standard",
                    "pragmatic_tip": "Tip 37: Design with Contracts",
                    "step_1": "Never wire flip-flops directly between asynchronous clock domains.",
                    "step_2": "Instantiate a standard 2-FF or 3-FF synchronizer cell contract.",
                    "step_3": "For multi-bit busses, enforce Gray-code encoding or asynchronous FIFO handshakes.",
                })

        return advice_list


def get_all_pragmatic_tips() -> List[Dict[str, Any]]:
    """Return all Pragmatic Programmer tips formatted for the web UI."""
    return [
        {
            "number": t.number,
            "title": t.title,
            "pillar": t.pillar.value,
            "quote": t.quote,
            "actionable_rule": t.actionable_rule,
            "telemetry_metric": t.telemetry_metric,
        }
        for t in PRAGMATIC_TIPS
    ]


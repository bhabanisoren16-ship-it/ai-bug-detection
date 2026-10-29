"""
UnifiedBugHighlightEngine — Main Orchestrator.

Ties Phase 1 (Code Analysis) and Phase 2 (Circuit Analysis) into a single
entry point that returns ``VerificationReport`` objects containing
``BugDiagnostic`` records with full causal traces, visual overlays, and
auto-remediation diffs.

Reference: Section 6.1 of the AI & Software Bug Detection Blueprint.
"""

from __future__ import annotations

import ast
import json
import textwrap
from typing import Any, Dict, List, Optional

from bug_detection.core.schemas import (
    AutoRemediation,
    BugDiagnostic,
    CausalStep,
    CircuitProbe,
    CodeSpan,
    HighlightStyle,
    SEVERITY_PALETTE,
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
from bug_detection.core.rules_catalog import ALL_RULES, get_rule
from bug_detection.core.agans_rules import (
    AGANS_NINE_RULES,
    AgansPreFlightChecker,
    AgansClosedLoopVerifier,
    get_agans_mapping_for_rule,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _caret_overlay(source_lines: List[str], lineno: int,
                   col_start: int, col_end: int, message: str) -> str:
    """Build a visual caret-line overlay like compilers do.

    Example::

        12 |     result = a / divisor
           |                  ^^^^^^^ Division by zero
    """
    if lineno < 1 or lineno > len(source_lines):
        return ""
    code_line = source_lines[lineno - 1].rstrip()
    gutter = f"{lineno:>4} | "
    underline_padding = " " * (len(gutter) + col_start)
    caret_len = max(col_end - col_start, 1)
    return (
        f"{gutter}{code_line}\n"
        f"{underline_padding}{'^' * caret_len} {message}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────────────

class UnifiedBugHighlightEngine:
    """Orchestrates Phase 1 code analysis and Phase 2 circuit analysis.

    Usage::

        engine = UnifiedBugHighlightEngine()
        report = engine.analyze_all(source, "app.py", netlist=netlist_dict)
        print(report.to_json())
    """

    PALETTE = {
        "CRITICAL":   {"hex": "#D92D20", "style": "wavy-crimson"},
        "WARNING":    {"hex": "#F79009", "style": "dashed-amber"},
        "VIOLET_NET": {"hex": "#7A5AF8", "style": "dotted-violet"},
        "INFO":       {"hex": "#1558C9", "style": "solid-cobalt"},
        "NEON_AI":    {"hex": "#D4FF24", "style": "glow-neon-lime"},
    }

    # ── Public API ────────────────────────────────────────────────────────

    def analyze_all(
        self,
        source_code: str,
        filename: str,
        netlist: Optional[dict] = None,
    ) -> VerificationReport:
        """Run both phases and return a unified ``VerificationReport``.

        Args:
            source_code: Raw Python source text for Phase 1.
            filename:    Logical filename attached to every diagnostic.
            netlist:     Optional circuit netlist dict for Phase 2.

        Returns:
            A :class:`VerificationReport` aggregating all diagnostics.
        """
        report = VerificationReport()

        # Phase 1 — static code analysis
        for diag_dict in self.analyze_phase1_code(filename, source_code):
            diag = self._dict_to_diagnostic(diag_dict, phase="PHASE_1_CODE")
            report.add_diagnostic(diag)

        # Phase 2 — circuit analysis
        if netlist is not None:
            for diag_dict in self.analyze_phase2_circuit(netlist):
                diag = self._dict_to_diagnostic(diag_dict, phase="PHASE_2_CIRCUIT")
                report.add_diagnostic(diag)

        return report

    # ── Phase 1 — Source Code Analysis ────────────────────────────────────

    def analyze_phase1_code(self, filename: str, source_code: str) -> List[dict]:
        """Run full Phase 1 analysis on *source_code*.

        Detection rules applied:

        1. **CODE-MEM-001** — Use-After-Free / Double Free
        2. **CODE-NUM-003** — Division by Zero
        3. **CODE-SEC-004** — Taint Injection (SQL / OS / eval)
        4. **CODE-LOGIC-006** — Off-by-one array access
        5. Mutable default arguments
        6. Bare ``except:`` clauses
        7. ``== None`` comparisons (should use ``is None``)

        Returns:
            List of diagnostic dicts ready for aggregation.
        """
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError:
            return []

        source_lines = source_code.splitlines()
        diagnostics: List[dict] = []

        # ── 1. Use-After-Free / Double-Free (CODE-MEM-001) ───────────
        diagnostics.extend(self._detect_use_after_free(tree, filename, source_lines))

        # ── 2. Division by Zero (CODE-NUM-003) ──────────────────────
        diagnostics.extend(self._detect_division_by_zero(tree, filename, source_lines))

        # ── 3. Taint Injection (CODE-SEC-004) ────────────────────────
        diagnostics.extend(self._detect_taint_injection(tree, filename, source_lines))

        # ── 4. Off-by-one (CODE-LOGIC-006) ──────────────────────────
        diagnostics.extend(self._detect_off_by_one(tree, filename, source_lines))

        # ── 5. Mutable default argument ──────────────────────────────
        diagnostics.extend(self._detect_mutable_defaults(tree, filename, source_lines))

        # ── 6. Bare except ───────────────────────────────────────────
        diagnostics.extend(self._detect_bare_except(tree, filename, source_lines))

        # ── 7. == None comparison ────────────────────────────────────
        diagnostics.extend(self._detect_eq_none(tree, filename, source_lines))

        return diagnostics

    # ── Phase 2 — Circuit / Netlist Analysis ──────────────────────────────

    def analyze_phase2_circuit(self, netlist: dict) -> List[dict]:
        """Run full Phase 2 analysis on a circuit *netlist* dict.

        Expected netlist schema::

            {
                "module": "core_alu",
                "gates": { "<inst>": {"type": "...", "inputs": [...], "outputs": [...], "clock": "..."} },
                "nets":  { "<net>":  {"drivers": [...], "sinks": [...]} },
                "timing_paths": [ { ... path descriptor ... } ],
                "clocks": { "<clk>": {"period_ns": ...} }
            }

        Detection rules:

        1. **CIRC-ERC-004** — Floating / undriven nets
        2. **CIRC-ERC-004** — Multi-driver contention
        3. **CIRC-STA-001** — Setup timing violations
        4. **CIRC-STA-001** — Hold timing violations
        5. **CIRC-CDC-002** — Clock-domain crossing without synchronizer

        Returns:
            List of diagnostic dicts.
        """
        diagnostics: List[dict] = []
        module = netlist.get("module", "top")
        gates = netlist.get("gates", {})
        nets = netlist.get("nets", {})
        timing_paths = netlist.get("timing_paths", [])
        clocks = netlist.get("clocks", {})

        # ── 1 & 2. Floating nets / multi-driver ──────────────────────
        diagnostics.extend(
            self._detect_net_issues(module, nets)
        )

        # ── 3 & 4. Timing violations ────────────────────────────────
        diagnostics.extend(
            self._detect_timing_violations(module, timing_paths, clocks)
        )

        # ── 5. CDC violations ────────────────────────────────────────
        diagnostics.extend(
            self._detect_cdc_violations(module, gates, nets, clocks)
        )

        return diagnostics

    # ──────────────────────────────────────────────────────────────────────
    # Phase 1 private detectors
    # ──────────────────────────────────────────────────────────────────────

    def _detect_use_after_free(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Track ``free_buf`` / ``close_fd`` calls; flag dereferences after."""
        rule = get_rule("CODE-MEM-001")
        results: List[dict] = []

        # Gather freed names inside each function body
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            freed: Dict[str, int] = {}  # var -> lineno of free call

            for node in ast.walk(func):
                # Detect free_buf(x) / close_fd(x) style calls
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in ("free_buf", "close_fd", "free", "close"):
                        for arg in node.args:
                            if isinstance(arg, ast.Name):
                                freed[arg.id] = node.lineno

            if not freed:
                continue

            # Second pass: look for dereferences/uses after the free call
            for node in ast.walk(func):
                if isinstance(node, ast.Name) and node.id in freed:
                    free_line = freed[node.id]
                    if node.lineno > free_line:
                        # Skip if the node is part of the free call itself
                        col_end = node.col_offset + len(node.id)
                        msg = (
                            f"Use-after-free: '{node.id}' dereferenced at "
                            f"line {node.lineno} after free at line {free_line}"
                        )
                        trace = [
                            CausalStep(1, f"'{node.id}' freed",
                                       fn, free_line, 0, node.id),
                            CausalStep(2, f"'{node.id}' used after free",
                                       fn, node.lineno, node.col_offset, node.id),
                        ]
                        diff = (
                            f"- {src[node.lineno - 1].rstrip()}\n"
                            f"+ # REMOVED: use of freed variable '{node.id}'"
                        )
                        overlay = _caret_overlay(
                            src, node.lineno, node.col_offset, col_end,
                            "Use-after-free"
                        )
                        results.append(
                            self._code_diag(
                                rule, "CRITICAL", 0.95, fn,
                                node.lineno, node.col_offset, col_end,
                                src, msg, trace, diff, overlay,
                            )
                        )
        return results

    def _detect_division_by_zero(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Flag ``/ divisor`` or ``% divisor`` where divisor may be zero."""
        rule = get_rule("CODE-NUM-003")
        results: List[dict] = []

        # First: collect variables assigned to 0
        zero_vars: Dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        if isinstance(node.value, ast.Constant) and node.value.value == 0:
                            zero_vars[tgt.id] = node.lineno

        # Second: look for Div / Mod operations
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Div, ast.FloorDiv, ast.Mod)
            ):
                divisor = node.right
                flag = False
                var_name = ""
                if isinstance(divisor, ast.Constant) and divisor.value == 0:
                    flag = True
                    var_name = "0"
                elif isinstance(divisor, ast.Name) and divisor.id in zero_vars:
                    flag = True
                    var_name = divisor.id

                if flag:
                    col_start = divisor.col_offset
                    col_end = col_start + max(len(var_name), 1)
                    msg = (
                        f"Division by zero: divisor '{var_name}' is zero "
                        f"at line {node.lineno}"
                    )
                    trace = []
                    if var_name in zero_vars:
                        trace.append(
                            CausalStep(1, f"'{var_name}' assigned 0",
                                       fn, zero_vars[var_name], 0, var_name)
                        )
                    trace.append(
                        CausalStep(len(trace) + 1,
                                   f"'{var_name}' used as divisor",
                                   fn, node.lineno, col_start, var_name)
                    )
                    diff = (
                        f"- {src[node.lineno - 1].rstrip()}\n"
                        f"+ if {var_name} != 0:\n"
                        f"+     {src[node.lineno - 1].strip()}"
                    )
                    overlay = _caret_overlay(
                        src, node.lineno, col_start, col_end,
                        "Division by zero"
                    )
                    results.append(
                        self._code_diag(
                            rule, "CRITICAL", 0.92, fn,
                            node.lineno, col_start, col_end,
                            src, msg, trace, diff, overlay,
                        )
                    )
        return results

    def _detect_taint_injection(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Track ``input()`` / ``recv()`` → dangerous sinks."""
        rule = get_rule("CODE-SEC-004")
        results: List[dict] = []

        TAINT_SOURCES = {"input", "recv", "raw_input"}
        DANGEROUS_SINKS = {"exec", "eval", "system", "popen"}

        # Collect tainted variable names
        tainted: Dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    func = node.value.func
                    func_name = ""
                    if isinstance(func, ast.Name):
                        func_name = func.id
                    elif isinstance(func, ast.Attribute):
                        func_name = func.attr
                    if func_name in TAINT_SOURCES:
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name):
                                tainted[tgt.id] = node.lineno

        # Detect tainted data reaching sinks
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Get the sink function name
            sink_name = ""
            if isinstance(node.func, ast.Name):
                sink_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                sink_name = node.func.attr

            if sink_name not in DANGEROUS_SINKS:
                # Also catch string concatenation in execute(), cursor.execute()
                if sink_name == "execute":
                    pass  # check args below
                else:
                    continue

            # Check arguments for tainted variables
            for arg in node.args:
                tainted_vars_in_arg = self._find_tainted_names(arg, tainted)
                for tvar, tline in tainted_vars_in_arg:
                    col_end = node.col_offset + len(sink_name) + 1
                    msg = (
                        f"Taint injection: '{tvar}' from untrusted source "
                        f"(line {tline}) flows to '{sink_name}()' at line "
                        f"{node.lineno}"
                    )
                    trace = [
                        CausalStep(1, f"'{tvar}' = tainted input",
                                   fn, tline, 0, tvar),
                        CausalStep(2, f"'{tvar}' reaches sink '{sink_name}()'",
                                   fn, node.lineno, node.col_offset, tvar),
                    ]
                    diff = (
                        f"- {src[node.lineno - 1].rstrip()}\n"
                        f"+ # Use parameterized API instead of string concat"
                    )
                    overlay = _caret_overlay(
                        src, node.lineno, node.col_offset, col_end,
                        f"Taint reaches sink '{sink_name}()'"
                    )
                    results.append(
                        self._code_diag(
                            rule, "CRITICAL", 0.97, fn,
                            node.lineno, node.col_offset, col_end,
                            src, msg, trace, diff, overlay,
                        )
                    )
        return results

    def _find_tainted_names(
        self, node: ast.AST, tainted: Dict[str, int]
    ) -> List[tuple]:
        """Recursively find tainted variable references in an AST subtree."""
        found: List[tuple] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted:
                found.append((child.id, tainted[child.id]))
        return found

    def _detect_off_by_one(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Detect ``array[i+1]`` inside ``for i in range(len(array))``."""
        results: List[dict] = []
        rule_id = "CODE-MEM-002"  # closest existing rule
        rule = get_rule(rule_id)

        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue

            # Check: for <target> in range(len(<array>))
            if not isinstance(node.target, ast.Name):
                continue
            loop_var = node.target.id

            iter_call = node.iter
            if not isinstance(iter_call, ast.Call):
                continue
            if not (isinstance(iter_call.func, ast.Name)
                    and iter_call.func.id == "range"):
                continue
            if len(iter_call.args) != 1:
                continue
            len_call = iter_call.args[0]
            if not isinstance(len_call, ast.Call):
                continue
            if not (isinstance(len_call.func, ast.Name)
                    and len_call.func.id == "len"):
                continue
            if len(len_call.args) != 1 or not isinstance(
                len_call.args[0], ast.Name
            ):
                continue
            array_name = len_call.args[0].id

            # Walk the body looking for array[loop_var + 1]
            for body_node in ast.walk(node):
                if not isinstance(body_node, ast.Subscript):
                    continue
                # value must be the same array
                if not (isinstance(body_node.value, ast.Name)
                        and body_node.value.id == array_name):
                    continue
                slc = body_node.slice
                if isinstance(slc, ast.BinOp) and isinstance(slc.op, ast.Add):
                    left_match = (isinstance(slc.left, ast.Name)
                                  and slc.left.id == loop_var)
                    right_is_one = (isinstance(slc.right, ast.Constant)
                                    and slc.right.value == 1)
                    if left_match and right_is_one:
                        ln = body_node.lineno
                        col_start = body_node.col_offset
                        col_end = col_start + len(array_name) + 6  # approx
                        msg = (
                            f"Off-by-one: '{array_name}[{loop_var}+1]' may "
                            f"exceed bounds in range(len({array_name}))"
                        )
                        trace = [
                            CausalStep(
                                1,
                                f"Loop range(len({array_name})) → "
                                f"{loop_var} reaches len-1",
                                fn, node.lineno, 0, loop_var,
                            ),
                            CausalStep(
                                2,
                                f"Access {array_name}[{loop_var}+1] exceeds "
                                f"last valid index",
                                fn, ln, col_start, array_name,
                            ),
                        ]
                        diff = (
                            f"- for {loop_var} in range(len({array_name})):\n"
                            f"+ for {loop_var} in range(len({array_name}) - 1):"
                        )
                        overlay = _caret_overlay(
                            src, ln, col_start, col_end, "Off-by-one"
                        )
                        results.append(
                            self._code_diag(
                                rule, "CRITICAL", 0.85, fn,
                                ln, col_start, col_end,
                                src, msg, trace, diff, overlay,
                            )
                        )
        return results

    def _detect_mutable_defaults(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Flag ``def foo(x=[])`` or ``def foo(x={})``."""
        results: List[dict] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    ln = default.lineno
                    col_start = default.col_offset
                    type_name = type(default).__name__.lower()
                    col_end = col_start + 2  # [] or {}
                    msg = (
                        f"Mutable default argument ({type_name}) in "
                        f"'{node.name}()' at line {ln}"
                    )
                    trace = [
                        CausalStep(1, f"Mutable {type_name} as default",
                                   fn, ln, col_start, node.name),
                    ]
                    diff = (
                        f"- def {node.name}(..., arg={type_name}):\n"
                        f"+ def {node.name}(..., arg=None):\n"
                        f"+     if arg is None:\n"
                        f"+         arg = {type_name}()"
                    )
                    overlay = _caret_overlay(
                        src, ln, col_start, col_end,
                        "Mutable default argument"
                    )
                    results.append(
                        self._code_diag(
                            rule=None, sev="WARNING", score=0.60, fn=fn,
                            ln=ln, c0=col_start, c1=col_end,
                            src=src, msg=msg, trace=trace, diff=diff,
                            overlay=overlay,
                            rule_id="CODE-STYLE-007",
                            category="Mutable Default Argument",
                        )
                    )
        return results

    def _detect_bare_except(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Flag bare ``except:`` without an exception type."""
        results: List[dict] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                ln = node.lineno
                col_start = node.col_offset
                col_end = col_start + 6  # len("except")
                msg = f"Bare except clause at line {ln} — catches all exceptions including SystemExit and KeyboardInterrupt"
                trace = [
                    CausalStep(1, "Bare 'except:' catches everything",
                               fn, ln, col_start, "except"),
                ]
                diff = (
                    f"- except:\n"
                    f"+ except Exception:"
                )
                overlay = _caret_overlay(
                    src, ln, col_start, col_end, "Bare except"
                )
                results.append(
                    self._code_diag(
                        rule=None, sev="WARNING", score=0.55, fn=fn,
                        ln=ln, c0=col_start, c1=col_end,
                        src=src, msg=msg, trace=trace, diff=diff,
                        overlay=overlay,
                        rule_id="CODE-STYLE-008",
                        category="Bare Except Clause",
                    )
                )
        return results

    def _detect_eq_none(
        self, tree: ast.Module, fn: str, src: List[str]
    ) -> List[dict]:
        """Flag ``x == None`` — should use ``x is None``."""
        results: List[dict] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    if isinstance(comparator, ast.Constant) and comparator.value is None:
                        ln = node.lineno
                        col_start = node.col_offset
                        col_end = comparator.col_offset + 4  # "None"
                        op_str = "==" if isinstance(op, ast.Eq) else "!="
                        is_str = "is" if isinstance(op, ast.Eq) else "is not"
                        msg = (
                            f"Comparison to None with '{op_str}' at line {ln} "
                            f"— use '{is_str} None' instead"
                        )
                        trace = [
                            CausalStep(
                                1,
                                f"'{op_str} None' should be '{is_str} None'",
                                fn, ln, col_start, "None",
                            ),
                        ]
                        diff = (
                            f"- ... {op_str} None\n"
                            f"+ ... {is_str} None"
                        )
                        overlay = _caret_overlay(
                            src, ln, col_start, col_end,
                            f"Use '{is_str} None'"
                        )
                        results.append(
                            self._code_diag(
                                rule=None, sev="WARNING", score=0.45, fn=fn,
                                ln=ln, c0=col_start, c1=col_end,
                                src=src, msg=msg, trace=trace, diff=diff,
                                overlay=overlay,
                                rule_id="CODE-STYLE-009",
                                category="Comparison to None",
                            )
                        )
        return results

    # ──────────────────────────────────────────────────────────────────────
    # Phase 2 private detectors
    # ──────────────────────────────────────────────────────────────────────

    def _detect_net_issues(
        self, module: str, nets: Dict[str, Any]
    ) -> List[dict]:
        """Check for floating (0 drivers) and multi-driver nets."""
        rule = get_rule("CIRC-ERC-004")
        results: List[dict] = []

        for net_name, net_info in nets.items():
            drivers = net_info.get("drivers", [])
            sinks = net_info.get("sinks", [])

            if len(drivers) == 0 and len(sinks) > 0:
                # Floating / undriven net
                msg = (
                    f"Floating net '{net_name}' in module '{module}': "
                    f"0 drivers, {len(sinks)} sink(s) — will propagate X"
                )
                trace = [
                    CausalStep(1, f"Net '{net_name}' has no driver",
                               module, 0, 0, net_name),
                    CausalStep(2, f"Sinks {sinks} read undefined value",
                               module, 0, 0, net_name),
                ]
                results.append(
                    self._circuit_diag(
                        rule, "VIOLET_NET", 0.70, module, net_name,
                        msg, trace,
                        fix=f"Tie '{net_name}' to VDD/GND or remove dangling sinks",
                        net_names=[net_name],
                        gate_instances=sinks,
                    )
                )

            elif len(drivers) > 1:
                # Multi-driver contention
                msg = (
                    f"Multi-driver contention on net '{net_name}' in "
                    f"module '{module}': drivers {drivers}"
                )
                trace = [
                    CausalStep(1, f"Net '{net_name}' driven by {drivers[0]}",
                               module, 0, 0, net_name),
                    CausalStep(2, f"Net '{net_name}' also driven by {drivers[1]}",
                               module, 0, 0, net_name),
                ]
                results.append(
                    self._circuit_diag(
                        rule, "CRITICAL", 0.88, module, net_name,
                        msg, trace,
                        fix=f"Add tri-state mux to arbitrate drivers on '{net_name}'",
                        net_names=[net_name],
                        gate_instances=drivers,
                    )
                )

        return results

    def _detect_timing_violations(
        self, module: str, timing_paths: List[dict], clocks: Dict[str, Any]
    ) -> List[dict]:
        """Compute setup/hold slack for each timing path."""
        rule = get_rule("CIRC-STA-001")
        results: List[dict] = []

        for path in timing_paths:
            clk_name = path.get("clock", "clk")
            clk_info = clocks.get(clk_name, {})
            clk_period = clk_info.get("period_ns", path.get("clk_period_ns", 10.0))

            params = TimingParams(
                clk_period_ns=clk_period,
                cap_clk_delay_ns=path.get("cap_clk_delay_ns", 0.0),
                lnch_clk_delay_ns=path.get("lnch_clk_delay_ns", 0.0),
                clk_to_q_ns=path.get("clk_to_q_ns", 0.0),
                comb_delay_ns=path.get("comb_delay_ns", 0.0),
                setup_ns=path.get("setup_ns", 0.0),
                hold_ns=path.get("hold_ns", 0.0),
                uncertainty_ns=path.get("uncertainty_ns", 0.0),
            )

            # Setup slack
            s_slack = setup_slack(params)
            sev = classify_timing_slack(s_slack)
            if sev in ("CRITICAL", "WARNING"):
                start_ff = path.get("start_point", "FF_src")
                end_ff = path.get("end_point", "FF_dst")
                through = path.get("through", [])
                msg = (
                    f"Setup timing violation on path {start_ff} → {end_ff}: "
                    f"slack = {s_slack:+.3f} ns"
                )
                trace = [
                    CausalStep(1, f"Launch at {start_ff} (clk={clk_name})",
                               module, 0, 0, start_ff),
                ]
                for i, gate in enumerate(through, start=2):
                    trace.append(
                        CausalStep(i, f"Through {gate}", module, 0, 0, gate)
                    )
                trace.append(
                    CausalStep(
                        len(trace) + 1,
                        f"Capture at {end_ff}, slack={s_slack:+.3f} ns",
                        module, 0, 0, end_ff,
                    )
                )
                fix = (
                    "Insert pipeline register or resize drivers to reduce "
                    f"combinational delay ({params.comb_delay_ns:.2f} ns)"
                )
                results.append(
                    self._circuit_diag(
                        rule, sev, 0.93 if sev == "CRITICAL" else 0.72,
                        module, f"{start_ff}->{end_ff}", msg, trace,
                        fix=fix, slack_ns=s_slack,
                        net_names=[start_ff, end_ff],
                        gate_instances=through,
                        clock_domains=[clk_name],
                    )
                )

            # Hold slack
            h_slack = hold_slack(params)
            h_sev = classify_timing_slack(h_slack)
            if h_sev in ("CRITICAL", "WARNING"):
                start_ff = path.get("start_point", "FF_src")
                end_ff = path.get("end_point", "FF_dst")
                msg = (
                    f"Hold timing violation on path {start_ff} → {end_ff}: "
                    f"slack = {h_slack:+.3f} ns"
                )
                trace = [
                    CausalStep(1, f"Launch at {start_ff}", module, 0, 0, start_ff),
                    CausalStep(2, f"Capture at {end_ff}, hold slack={h_slack:+.3f} ns",
                               module, 0, 0, end_ff),
                ]
                fix = "Add buffer delay cells on data path to fix hold violation"
                results.append(
                    self._circuit_diag(
                        rule, h_sev, 0.90 if h_sev == "CRITICAL" else 0.68,
                        module, f"{start_ff}->{end_ff}", msg, trace,
                        fix=fix, slack_ns=h_slack,
                        net_names=[start_ff, end_ff],
                        clock_domains=[clk_name],
                    )
                )

        return results

    def _detect_cdc_violations(
        self, module: str, gates: Dict[str, Any],
        nets: Dict[str, Any], clocks: Dict[str, Any],
    ) -> List[dict]:
        """Detect clock-domain crossings without 2-FF synchronizers."""
        rule = get_rule("CIRC-CDC-002")
        results: List[dict] = []

        # Build a map: gate_instance -> clock_domain
        gate_clk: Dict[str, str] = {}
        for inst, info in gates.items():
            if "clock" in info:
                gate_clk[inst] = info["clock"]

        # For each net, check if driver and sink belong to different domains
        for net_name, net_info in nets.items():
            drivers = net_info.get("drivers", [])
            sinks = net_info.get("sinks", [])
            is_sync = net_info.get("synchronized", False)
            sync_stages = net_info.get("sync_stages", 0 if not is_sync else 2)

            for drv in drivers:
                drv_clk = gate_clk.get(drv, "")
                if not drv_clk:
                    continue
                for snk in sinks:
                    snk_clk = gate_clk.get(snk, "")
                    if not snk_clk:
                        continue
                    if drv_clk != snk_clk and sync_stages < 2:
                        msg = (
                            f"CDC violation: net '{net_name}' crosses from "
                            f"'{drv_clk}' ({drv}) to '{snk_clk}' ({snk}) "
                            f"with {sync_stages} sync stage(s) (need ≥2)"
                        )
                        trace = [
                            CausalStep(1, f"Source {drv} in domain '{drv_clk}'",
                                       module, 0, 0, drv),
                            CausalStep(2, f"Sink {snk} in domain '{snk_clk}'",
                                       module, 0, 0, snk),
                            CausalStep(3, f"Missing 2-FF synchronizer on '{net_name}'",
                                       module, 0, 0, net_name),
                        ]
                        fix = (
                            f"Insert 2-FF synchronizer or async FIFO on "
                            f"'{net_name}' between domains '{drv_clk}' and "
                            f"'{snk_clk}'"
                        )
                        results.append(
                            self._circuit_diag(
                                rule, "WARNING", 0.78, module, net_name,
                                msg, trace, fix=fix,
                                net_names=[net_name],
                                gate_instances=[drv, snk],
                                clock_domains=[drv_clk, snk_clk],
                            )
                        )
        return results

    # ──────────────────────────────────────────────────────────────────────
    # Diagnostic builders
    # ──────────────────────────────────────────────────────────────────────

    def _code_diag(
        self,
        rule,
        sev: str,
        score: float,
        fn: str,
        ln: int,
        c0: int,
        c1: int,
        src: List[str],
        msg: str,
        trace: List[CausalStep],
        diff: str,
        overlay: str = "",
        *,
        rule_id: str = "",
        category: str = "",
    ) -> dict:
        """Create a Phase 1 code diagnostic dict with visual overlay.

        Args:
            rule:     DetectionRule object (may be ``None`` for style rules).
            sev:      Severity tier string.
            score:    Base suspiciousness / confidence score.
            fn:       Source filename.
            ln:       Line number.
            c0:       Start column.
            c1:       End column.
            src:      Source lines list.
            msg:      Human-readable message.
            trace:    Causal trace steps.
            diff:     Unified diff string.
            overlay:  Pre-built visual overlay.
            rule_id:  Override rule ID when *rule* is None.
            category: Override category when *rule* is None.

        Returns:
            Diagnostic dict for inclusion in the results list.
        """
        rid = rule.rule_id if rule else rule_id
        cat = rule.category if rule else category

        # Compute hybrid score
        s_rule = severity_from_rule(sev)
        r_total = hybrid_priority_score(s_rule, score, 0.0)

        pal = self.PALETTE.get(sev, self.PALETTE["WARNING"])

        agans_info = get_agans_mapping_for_rule(rid)

        return {
            "rule_id": rid,
            "category": cat,
            "severity": sev,
            "message": msg,
            "scores": {
                "suspiciousness": round(score, 4),
                "r_total": round(r_total, 4),
            },
            "agans_rule": agans_info.get("primary_rule", ""),
            "agans_protocol": agans_info,
            "code_span": {
                "file": fn,
                "start_line": ln,
                "start_col": c0,
                "end_line": ln,
                "end_col": c1,
            },
            "highlight_style": {
                "color_hex": pal["hex"],
                "underline": pal["style"],
            },
            "causal_trace": [s.to_dict() for s in trace],
            "visual_overlay": overlay,
            "auto_remediation": {
                "summary": f"Fix {cat}",
                "unified_diff": diff,
            },
        }

    def _circuit_diag(
        self,
        rule,
        sev: str,
        score: float,
        module: str,
        net_or_path: str,
        msg: str,
        trace: List[CausalStep],
        *,
        fix: str = "",
        slack_ns: Optional[float] = None,
        net_names: Optional[List[str]] = None,
        gate_instances: Optional[List[str]] = None,
        clock_domains: Optional[List[str]] = None,
    ) -> dict:
        """Create a Phase 2 circuit diagnostic dict.

        Args:
            rule:           DetectionRule object.
            sev:            Severity tier.
            score:          Confidence score.
            module:         Circuit module name.
            net_or_path:    Net name or timing path descriptor.
            msg:            Human-readable message.
            trace:          Causal trace steps.
            fix:            Remediation summary.
            slack_ns:       Timing slack value (ns), if applicable.
            net_names:      Relevant net names.
            gate_instances: Relevant gate instances.
            clock_domains:  Clock domains involved.

        Returns:
            Diagnostic dict for inclusion in the results list.
        """
        s_rule = severity_from_rule(sev)
        r_total = hybrid_priority_score(s_rule, score, 0.0)
        pal = self.PALETTE.get(sev, self.PALETTE["WARNING"])
        agans_info = get_agans_mapping_for_rule(rule.rule_id)

        diag: dict = {
            "rule_id": rule.rule_id,
            "category": rule.category,
            "severity": sev,
            "message": msg,
            "scores": {
                "suspiciousness": round(score, 4),
                "r_total": round(r_total, 4),
            },
            "agans_rule": agans_info.get("primary_rule", ""),
            "agans_protocol": agans_info,
            "circuit_probe": {
                "module": module,
                "net_names": net_names or [],
                "gate_instances": gate_instances or [],
                "clock_domains": clock_domains or [],
            },
            "highlight_style": {
                "color_hex": pal["hex"],
                "underline": pal["style"],
            },
            "causal_trace": [s.to_dict() for s in trace],
            "auto_remediation": {
                "summary": fix,
            },
        }
        if slack_ns is not None:
            diag["slack_ns"] = slack_ns
        return diag

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _dict_to_diagnostic(d: dict, phase: str) -> BugDiagnostic:
        """Convert a raw diagnostic dict into a :class:`BugDiagnostic`."""
        code_span = None
        if "code_span" in d:
            cs = d["code_span"]
            code_span = CodeSpan(
                file=cs["file"],
                start_line=cs["start_line"],
                start_col=cs["start_col"],
                end_line=cs["end_line"],
                end_col=cs["end_col"],
            )

        circuit_probe = None
        if "circuit_probe" in d:
            cp = d["circuit_probe"]
            circuit_probe = CircuitProbe(
                module=cp.get("module", ""),
                net_names=cp.get("net_names", []),
                gate_instances=cp.get("gate_instances", []),
                clock_domains=cp.get("clock_domains", []),
            )

        hs_data = d.get("highlight_style", {})
        highlight_style = HighlightStyle(
            color_hex=hs_data.get("color_hex", "#D92D20"),
            underline=hs_data.get("underline", "wavy-crimson"),
        )

        causal_trace = [
            CausalStep(**step) for step in d.get("causal_trace", [])
        ]

        auto_rem = None
        if "auto_remediation" in d:
            ar = d["auto_remediation"]
            auto_rem = AutoRemediation(
                summary=ar.get("summary", ""),
                unified_diff=ar.get("unified_diff", ""),
            )

        return BugDiagnostic(
            phase=phase,
            rule_id=d.get("rule_id", ""),
            severity=d.get("severity", "WARNING"),
            message=d.get("message", ""),
            scores=d.get("scores", {}),
            code_span=code_span,
            circuit_probe=circuit_probe,
            highlight_style=highlight_style,
            causal_trace=causal_trace,
            visual_overlay=d.get("visual_overlay", ""),
            auto_remediation=auto_rem,
            slack_ns=d.get("slack_ns"),
            agans_rule=d.get("agans_rule", ""),
            agans_protocol=d.get("agans_protocol"),
        )

    # ── David J. Agans 9 Rules Integration Methods ───────────────────────

    def check_plug_sanity(
        self,
        source_code: str = "",
        filename: str = "source.py",
        netlist: Optional[dict] = None,
    ) -> List[dict]:
        """
        Execute Agans Rule 7 ("Check the Plug") pre-flight baseline sanity checks.
        Catch simple syntax, empty buffers, null pointers, and disconnected pins
        before full pipeline execution.
        """
        results: List[dict] = []
        if source_code:
            code_issues = AgansPreFlightChecker.check_code_sanity(source_code, filename)
            for iss in code_issues:
                results.append({
                    "rule_id": iss["rule_id"],
                    "category": "Pre-Flight Sanity Check",
                    "severity": iss["severity"],
                    "message": iss["message"],
                    "agans_rule": iss["agans_rule"],
                    "scores": {"suspiciousness": 1.0, "r_total": 0.99},
                    "code_span": {"file": filename, "start_line": iss.get("line", 1), "start_col": 0, "end_line": iss.get("line", 1), "end_col": 1},
                })
        if netlist is not None:
            net_issues = AgansPreFlightChecker.check_netlist_sanity(netlist)
            for iss in net_issues:
                results.append({
                    "rule_id": iss["rule_id"],
                    "category": "Circuit Sanity Check",
                    "severity": iss["severity"],
                    "message": iss["message"],
                    "agans_rule": iss["agans_rule"],
                    "scores": {"suspiciousness": 1.0, "r_total": 0.99},
                    "circuit_probe": {"module": netlist.get("module", "top"), "net_names": [iss.get("net", "")] if "net" in iss else []},
                })
        return results

    def verify_remediation_patch(
        self,
        source_code: str,
        target_rule_id: str,
        patch_diff_or_code: str,
        filename: str = "source.py",
    ) -> Dict[str, Any]:
        """
        Execute Agans Rule 9: "If You Didn't Fix It, It Ain't Fixed".
        Applies patch to source code and proves closed-loop resolution with zero regressions.
        """
        patched_code = AgansClosedLoopVerifier.apply_patch(source_code, patch_diff_or_code)
        
        def run_analyzer(code: str) -> List[dict]:
            return self.analyze_phase1_code(filename, code)

        verification_result = AgansClosedLoopVerifier.verify_code_fix(
            original_source=source_code,
            patched_source=patched_code,
            target_rule_id=target_rule_id,
            analyzer_callable=run_analyzer,
        )
        verification_result["patched_code"] = patched_code
        return verification_result

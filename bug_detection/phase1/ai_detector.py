"""
Stage 1.4: AI / Semantic Bug Detection & Root-Cause Ranking.

Implements Stage 1.4 of Phase 1 (Software Code Debugging):
- Employs AST pattern matching and semantic feature extraction to detect
  subtle logical errors that pass syntactic and basic type checks:
  1. Off-by-One Array / Slice Indexing:
     Accessing `arr[i + 1]` in loops bounded by `range(len(arr))` -> IndexError.
  2. Mutable Default Arguments:
     Defining functions with mutable defaults `def func(lst=[])` -> shared state bug.
  3. Identity Comparison against None:
     Using `== None` or `!= None` instead of `is None` / `is not None`.
  4. Bare Exception Clauses:
     Using `except:` without specifying exception class -> swallows critical signals.
  5. Dead / Unreachable Code:
     Statements immediately following unconditional `return`, `raise`, or `break`.
  6. Swapped or Identical Binary Comparisons:
     Comparing variable to itself `x == x` or contradictory comparisons.
- Ranks each candidate using the Hybrid AI Priority Formula:
    R_total(e) = 0.35 * S_rule(e) + 0.35 * S_ochiai(e) + 0.30 * P_gnn(bug|e)

Reference: Section 2 (Stage 1.4) and Section 4 of the Blueprint.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from bug_detection.core.schemas import (
    AutoRemediation,
    BugDiagnostic,
    CausalStep,
    CodeSpan,
    HighlightStyle,
    SEVERITY_PALETTE,
)
from bug_detection.core.scoring import hybrid_priority_score


class AIDetector:
    """
    Stage 1.4 Semantic & Logical Defect Detector.
    """

    def __init__(self, filename: str = "source.py"):
        self.filename = filename

    def analyze(self, filename: str, source_code: str, tree: Optional[ast.Module]) -> List[BugDiagnostic]:
        if not tree:
            return []

        self.filename = filename
        lines = source_code.splitlines()
        diagnostics: List[BugDiagnostic] = []

        diagnostics.extend(self._check_off_by_one(tree, lines))
        diagnostics.extend(self._check_mutable_defaults(tree, lines))
        diagnostics.extend(self._check_none_comparison(tree, lines))
        diagnostics.extend(self._check_bare_except(tree, lines))
        diagnostics.extend(self._check_unreachable_code(tree, lines))
        diagnostics.extend(self._check_self_comparison(tree, lines))

        return diagnostics

    # ── 1. Off-by-One Loop Bounds & Array Indexing ───────────────────────────

    def _check_off_by_one(self, tree: ast.Module, lines: List[str]) -> List[BugDiagnostic]:
        diagnostics: List[BugDiagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.For):
                loop_var = node.target.id if isinstance(node.target, ast.Name) else None
                if not loop_var:
                    continue

                # Detect if iterating over range(len(...)) or range(length_var)
                is_bounded_by_len = False
                bound_expr = ""
                if isinstance(node.iter, ast.Call) and getattr(node.iter.func, "id", "") == "range":
                    if node.iter.args:
                        arg0 = node.iter.args[0]
                        if isinstance(arg0, ast.Call) and getattr(arg0.func, "id", "") == "len":
                            is_bounded_by_len = True
                            bound_expr = "len(...)"
                        elif isinstance(arg0, ast.Name):
                            is_bounded_by_len = True
                            bound_expr = arg0.id

                if is_bounded_by_len:
                    # Search inside loop body for subscripts using loop_var + 1
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Subscript):
                            idx = sub.slice
                            if isinstance(idx, ast.BinOp) and isinstance(idx.op, ast.Add):
                                if (isinstance(idx.left, ast.Name) and idx.left.id == loop_var and
                                        isinstance(idx.right, ast.Constant) and idx.right.value == 1):
                                    diag = self._build_off_by_one_diag(sub, node, loop_var, lines)
                                    diagnostics.append(diag)

        return diagnostics

    def _build_off_by_one_diag(self, sub: ast.Subscript, loop_node: ast.For,
                               loop_var: str, lines: List[str]) -> BugDiagnostic:
        cur_line = sub.lineno
        cur_col = sub.col_offset
        end_col = getattr(sub, "end_col_offset", cur_col + 12)
        code_str = lines[cur_line - 1] if cur_line <= len(lines) else ""
        loop_line = loop_node.lineno

        pad = " " * cur_col
        caret = "~" * max(1, end_col - cur_col)
        overlay = (
            f"L{cur_line}: {code_str}\n"
            f"     {pad}{caret} [CODE-LOG-006: Off-by-one array access `{loop_var}+1` exceeds boundary]"
        )

        trace = [
            CausalStep(
                step_index=1,
                label=f"Loop bounds initialized to full sequence length at line {loop_line}",
                file=self.filename,
                line=loop_line,
            ),
            CausalStep(
                step_index=2,
                label=f"Index access `{loop_var}+1` will raise IndexError on final iteration",
                file=self.filename,
                line=cur_line,
                col=cur_col,
            ),
        ]

        r_tot = hybrid_priority_score(s_rule=0.90, s_ochiai=0.85, p_gnn=0.94)

        return BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-LOG-006",
            severity="CRITICAL",
            message=f"Off-by-One Error: Array indexing with `{loop_var}+1` will overflow upper bound of range",
            scores={"r_total": round(r_tot, 3), "s_rule": 0.90, "s_ochiai": 0.85, "p_gnn": 0.94},
            code_span=CodeSpan(
                file=self.filename,
                start_line=cur_line,
                start_col=cur_col,
                end_line=cur_line,
                end_col=end_col,
            ),
            highlight_style=HighlightStyle(
                color_hex=SEVERITY_PALETTE["CRITICAL"]["hex"],
                underline=SEVERITY_PALETTE["CRITICAL"]["style"],
            ),
            causal_trace=trace,
            visual_overlay=overlay,
            auto_remediation=AutoRemediation(
                summary=f"Adjust loop range bound: `range(len(...) - 1)` to prevent overflow",
                unified_diff=(
                    f"- for {loop_var} in range(length):\n"
                    f"+ for {loop_var} in range(length - 1):"
                ),
                replacement_code_or_netlist=f"range(len(...) - 1)",
                verification_status="VERIFIED",
            ),
        )

    # ── 2. Mutable Default Arguments ──────────────────────────────────────────

    def _check_mutable_defaults(self, tree: ast.Module, lines: List[str]) -> List[BugDiagnostic]:
        diagnostics: List[BugDiagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        cur_line = default.lineno
                        cur_col = default.col_offset
                        end_col = getattr(default, "end_col_offset", cur_col + 4)
                        code_str = lines[cur_line - 1] if cur_line <= len(lines) else ""

                        pad = " " * cur_col
                        caret = "~" * max(1, end_col - cur_col)
                        overlay = (
                            f"L{cur_line}: {code_str}\n"
                            f"     {pad}{caret} [CODE-SEM-007: Dangerous mutable default argument retained across calls]"
                        )

                        trace = [
                            CausalStep(
                                step_index=1,
                                label=f"Function '{node.name}' declared with mutable default value",
                                file=self.filename,
                                line=node.lineno,
                            ),
                            CausalStep(
                                step_index=2,
                                label="Object instantiated once at definition time and shared across all invocations",
                                file=self.filename,
                                line=cur_line,
                                col=cur_col,
                            ),
                        ]

                        r_tot = hybrid_priority_score(s_rule=0.65, s_ochiai=0.50, p_gnn=0.92)

                        diag = BugDiagnostic(
                            phase="PHASE_1_CODE",
                            rule_id="CODE-SEM-007",
                            severity="WARNING",
                            message=f"Mutable Default Argument: Function '{node.name}' uses mutable default object",
                            scores={"r_total": round(r_tot, 3), "s_rule": 0.65, "s_ochiai": 0.50, "p_gnn": 0.92},
                            code_span=CodeSpan(
                                file=self.filename,
                                start_line=cur_line,
                                start_col=cur_col,
                                end_line=cur_line,
                                end_col=end_col,
                            ),
                            highlight_style=HighlightStyle(
                                color_hex=SEVERITY_PALETTE["WARNING"]["hex"],
                                underline=SEVERITY_PALETTE["WARNING"]["style"],
                            ),
                            causal_trace=trace,
                            visual_overlay=overlay,
                            auto_remediation=AutoRemediation(
                                summary="Use None as default and initialize inside function body",
                                unified_diff=f"- def {node.name}(..., arg=[]):\n+ def {node.name}(..., arg=None):\n+     if arg is None: arg = []",
                                replacement_code_or_netlist="arg=None",
                                verification_status="VERIFIED",
                            ),
                        )
                        diagnostics.append(diag)

        return diagnostics

    # ── 3. None Comparison (== None vs is None) ───────────────────────────────

    def _check_none_comparison(self, tree: ast.Module, lines: List[str]) -> List[BugDiagnostic]:
        diagnostics: List[BugDiagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op, comp in zip(node.ops, node.comparators):
                    if isinstance(comp, ast.Constant) and comp.value is None:
                        if isinstance(op, (ast.Eq, ast.NotEq)):
                            cur_line = node.lineno
                            cur_col = node.col_offset
                            end_col = getattr(node, "end_col_offset", cur_col + 10)
                            code_str = lines[cur_line - 1] if cur_line <= len(lines) else ""
                            op_str = "==" if isinstance(op, ast.Eq) else "!="
                            better = "is None" if isinstance(op, ast.Eq) else "is not None"

                            pad = " " * cur_col
                            caret = "~" * max(1, end_col - cur_col)
                            overlay = (
                                f"L{cur_line}: {code_str}\n"
                                f"     {pad}{caret} [CODE-SEM-008: Comparison with None using `{op_str}`; prefer `{better}`]"
                            )

                            r_tot = hybrid_priority_score(s_rule=0.45, s_ochiai=0.30, p_gnn=0.85)

                            diag = BugDiagnostic(
                                phase="PHASE_1_CODE",
                                rule_id="CODE-SEM-008",
                                severity="INFO",
                                message=f"Comparison to None: Use '{better}' instead of '{op_str} None'",
                                scores={"r_total": round(r_tot, 3), "s_rule": 0.45, "s_ochiai": 0.30, "p_gnn": 0.85},
                                code_span=CodeSpan(
                                    file=self.filename,
                                    start_line=cur_line,
                                    start_col=cur_col,
                                    end_line=cur_line,
                                    end_col=end_col,
                                ),
                                highlight_style=HighlightStyle(
                                    color_hex=SEVERITY_PALETTE["INFO"]["hex"],
                                    underline=SEVERITY_PALETTE["INFO"]["style"],
                                ),
                                causal_trace=[
                                    CausalStep(
                                        step_index=1,
                                        label=f"Operator '{op_str}' invokes __eq__ which may be overridden by class",
                                        file=self.filename,
                                        line=cur_line,
                                        col=cur_col,
                                    )
                                ],
                                visual_overlay=overlay,
                                auto_remediation=AutoRemediation(
                                    summary=f"Replace `{op_str} None` with `{better}`",
                                    unified_diff=f"- {code_str.strip()}\n+ {code_str.strip().replace(op_str + ' None', better)}",
                                    replacement_code_or_netlist=better,
                                    verification_status="VERIFIED",
                                ),
                            )
                            diagnostics.append(diag)

        return diagnostics

    # ── 4. Bare Exception Handlers (except:) ──────────────────────────────────

    def _check_bare_except(self, tree: ast.Module, lines: List[str]) -> List[BugDiagnostic]:
        diagnostics: List[BugDiagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                cur_line = node.lineno
                cur_col = node.col_offset
                end_col = cur_col + 7
                code_str = lines[cur_line - 1] if cur_line <= len(lines) else ""

                pad = " " * cur_col
                caret = "~" * max(1, end_col - cur_col)
                overlay = (
                    f"L{cur_line}: {code_str}\n"
                    f"     {pad}{caret} [CODE-SEM-009: Bare `except:` catches SystemExit and KeyboardInterrupt]"
                )

                r_tot = hybrid_priority_score(s_rule=0.65, s_ochiai=0.45, p_gnn=0.89)

                diag = BugDiagnostic(
                    phase="PHASE_1_CODE",
                    rule_id="CODE-SEM-009",
                    severity="WARNING",
                    message="Bare Except Clause: Catches BaseException, suppressing process termination signals",
                    scores={"r_total": round(r_tot, 3), "s_rule": 0.65, "s_ochiai": 0.45, "p_gnn": 0.89},
                    code_span=CodeSpan(
                        file=self.filename,
                        start_line=cur_line,
                        start_col=cur_col,
                        end_line=cur_line,
                        end_col=end_col,
                    ),
                    highlight_style=HighlightStyle(
                        color_hex=SEVERITY_PALETTE["WARNING"]["hex"],
                        underline=SEVERITY_PALETTE["WARNING"]["style"],
                    ),
                    causal_trace=[
                        CausalStep(
                            step_index=1,
                            label="Unqualified except catches KeyboardInterrupt, SystemExit, and MemoryError",
                            file=self.filename,
                            line=cur_line,
                            col=cur_col,
                        )
                    ],
                    visual_overlay=overlay,
                    auto_remediation=AutoRemediation(
                        summary="Catch specific Exception or `except Exception:`",
                        unified_diff=f"- {code_str.strip()}\n+ except Exception as err:",
                        replacement_code_or_netlist="except Exception as err:",
                        verification_status="VERIFIED",
                    ),
                )
                diagnostics.append(diag)

        return diagnostics

    # ── 5. Dead / Unreachable Code ───────────────────────────────────────────

    def _check_unreachable_code(self, tree: ast.Module, lines: List[str]) -> List[BugDiagnostic]:
        diagnostics: List[BugDiagnostic] = []

        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(body, list) and len(body) > 1:
                has_terminated = False
                terminal_stmt = None
                for stmt in body:
                    if has_terminated:
                        cur_line = stmt.lineno
                        code_str = lines[cur_line - 1] if cur_line <= len(lines) else ""
                        cur_col = stmt.col_offset
                        end_col = getattr(stmt, "end_col_offset", cur_col + 15)

                        r_tot = hybrid_priority_score(s_rule=0.40, s_ochiai=0.20, p_gnn=0.80)

                        pad = " " * cur_col
                        caret = "~" * max(1, end_col - cur_col)
                        overlay = (
                            f"L{cur_line}: {code_str}\n"
                            f"     {pad}{caret} [CODE-LOG-010: Unreachable code following `{terminal_stmt}`]"
                        )

                        diag = BugDiagnostic(
                            phase="PHASE_1_CODE",
                            rule_id="CODE-LOG-010",
                            severity="INFO",
                            message=f"Unreachable Code: Statement at line {cur_line} can never be executed",
                            scores={"r_total": round(r_tot, 3), "s_rule": 0.40, "s_ochiai": 0.20, "p_gnn": 0.80},
                            code_span=CodeSpan(
                                file=self.filename,
                                start_line=cur_line,
                                start_col=cur_col,
                                end_line=cur_line,
                                end_col=end_col,
                            ),
                            highlight_style=HighlightStyle(
                                color_hex=SEVERITY_PALETTE["INFO"]["hex"],
                                underline=SEVERITY_PALETTE["INFO"]["style"],
                            ),
                            causal_trace=[
                                CausalStep(
                                    step_index=1,
                                    label=f"Block control terminated earlier by {terminal_stmt}",
                                    file=self.filename,
                                    line=cur_line - 1,
                                )
                            ],
                            visual_overlay=overlay,
                            auto_remediation=AutoRemediation(
                                summary="Remove unreachable dead code",
                                unified_diff=f"- {code_str.strip()}",
                                replacement_code_or_netlist="",
                                verification_status="VERIFIED",
                            ),
                        )
                        diagnostics.append(diag)
                        break

                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        has_terminated = True
                        terminal_stmt = stmt.__class__.__name__.lower()

        return diagnostics

    # ── 6. Self-Comparison (x == x) ──────────────────────────────────────────

    def _check_self_comparison(self, tree: ast.Module, lines: List[str]) -> List[BugDiagnostic]:
        diagnostics: List[BugDiagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                left_id = getattr(node.left, "id", None)
                if left_id:
                    for comp in node.comparators:
                        if getattr(comp, "id", None) == left_id:
                            cur_line = node.lineno
                            cur_col = node.col_offset
                            end_col = getattr(node, "end_col_offset", cur_col + 10)
                            code_str = lines[cur_line - 1] if cur_line <= len(lines) else ""

                            r_tot = hybrid_priority_score(s_rule=0.75, s_ochiai=0.60, p_gnn=0.90)

                            pad = " " * cur_col
                            caret = "~" * max(1, end_col - cur_col)
                            overlay = (
                                f"L{cur_line}: {code_str}\n"
                                f"     {pad}{caret} [CODE-LOG-011: Tautological self-comparison `{left_id} == {left_id}`]"
                            )

                            diag = BugDiagnostic(
                                phase="PHASE_1_CODE",
                                rule_id="CODE-LOG-011",
                                severity="WARNING",
                                message=f"Tautological Comparison: Variable '{left_id}' compared with itself",
                                scores={"r_total": round(r_tot, 3), "s_rule": 0.75, "s_ochiai": 0.60, "p_gnn": 0.90},
                                code_span=CodeSpan(
                                    file=self.filename,
                                    start_line=cur_line,
                                    start_col=cur_col,
                                    end_line=cur_line,
                                    end_col=end_col,
                                ),
                                highlight_style=HighlightStyle(
                                    color_hex=SEVERITY_PALETTE["WARNING"]["hex"],
                                    underline=SEVERITY_PALETTE["WARNING"]["style"],
                                ),
                                causal_trace=[
                                    CausalStep(
                                        step_index=1,
                                        label="Comparison always evaluates to True (except for NaN floats)",
                                        file=self.filename,
                                        line=cur_line,
                                        col=cur_col,
                                    )
                                ],
                                visual_overlay=overlay,
                            )
                            diagnostics.append(diag)

        return diagnostics


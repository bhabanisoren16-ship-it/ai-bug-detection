"""
Stage 1.1: Incremental Lexical, Syntactic & Lossless AST Indexing.

Implements Stage 1.1 of Phase 1 (Software Code Debugging):
- Robust AST parsing with error recovery / graceful failure modes.
- Annotates AST nodes with 5-tuple source coordinates:
  Span(n) = (file_id, start_line, start_col, end_line, end_col) + byte offsets.
- Detects lexical and syntactic errors and generates primary red squiggly
  diagnostic highlights without aborting downstream analysis of valid sections.
- Computes character and byte offset mapping for lossless editor overlays.

Reference: Section 2, Stage 1.1 of the AI & Software Bug Detection Blueprint.
"""

from __future__ import annotations

import ast
import re
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


@dataclass
class SourceMap:
    """Provides line-to-byte and column-to-byte index translation for lossless spans."""
    file_id: str
    source_code: str
    lines: List[str] = field(default_factory=list)
    line_offsets: List[int] = field(default_factory=list)

    def __post_init__(self):
        self.lines = self.source_code.splitlines(keepends=True)
        self.line_offsets = []
        offset = 0
        for line in self.lines:
            self.line_offsets.append(offset)
            offset += len(line.encode("utf-8"))
        if not self.line_offsets:
            self.line_offsets = [0]

    def line_col_to_byte(self, line: int, col: int) -> int:
        """Converts 1-indexed line and 0-indexed column to UTF-8 byte offset."""
        if line < 1 or line > len(self.line_offsets):
            return 0
        base = self.line_offsets[line - 1]
        line_text = self.lines[line - 1] if line <= len(self.lines) else ""
        prefix = line_text[:col]
        return base + len(prefix.encode("utf-8"))

    def get_span(self, start_line: int, start_col: int,
                 end_line: int, end_col: int) -> CodeSpan:
        """Constructs an exact 5-tuple CodeSpan with byte offsets."""
        b_start = self.line_col_to_byte(start_line, start_col)
        b_end = self.line_col_to_byte(end_line, end_col)
        if b_end < b_start:
            b_end = b_start + 1
        return CodeSpan(
            file=self.file_id,
            start_line=start_line,
            start_col=start_col,
            end_line=end_line,
            end_col=end_col,
            byte_offset_start=b_start,
            byte_offset_end=b_end,
        )


class ASTNodeIndexer(ast.NodeVisitor):
    """Walks an AST and enriches each node with full span and parent metadata."""

    def __init__(self, source_map: SourceMap):
        self.source_map = source_map
        self.parent_map: Dict[ast.AST, ast.AST] = {}
        self.spans: Dict[ast.AST, CodeSpan] = {}
        self.indexed_nodes: List[ast.AST] = []

    def visit(self, node: ast.AST):
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        end_lineno = getattr(node, "end_lineno", lineno)
        end_col_offset = getattr(node, "end_col_offset", col_offset + 1)

        span = self.source_map.get_span(lineno, col_offset, end_lineno, end_col_offset)
        node._span = span  # type: ignore[attr-defined]
        self.spans[node] = span
        self.indexed_nodes.append(node)

        for child in ast.iter_child_nodes(node):
            self.parent_map[child] = node
            self.visit(child)


class ASTAnalyzer:
    """
    Stage 1.1 Analyzer.

    Parses source code into an enriched AST, manages error recovery on invalid syntax,
    and produces primary syntax error diagnostics formatted per the blueprint.
    """

    def __init__(self, default_file_id: str = "source.py"):
        self.default_file_id = default_file_id

    def analyze(self, filename: str, source_code: str) -> Tuple[Optional[ast.Module], List[BugDiagnostic], SourceMap]:
        """
        Parses the source code, builds the source map, and performs syntactic indexing.

        Returns:
            (ast_tree, diagnostics, source_map)
        """
        fn = filename or self.default_file_id
        source_map = SourceMap(file_id=fn, source_code=source_code)
        diagnostics: List[BugDiagnostic] = []
        tree: Optional[ast.Module] = None

        try:
            tree = ast.parse(source_code, filename=fn)
            indexer = ASTNodeIndexer(source_map)
            indexer.visit(tree)
            tree._indexer = indexer  # type: ignore[attr-defined]
        except SyntaxError as syn_err:
            diag = self._create_syntax_diagnostic(syn_err, fn, source_map)
            diagnostics.append(diag)

            # Error recovery attempt: try parsing with bad line blanked out
            tree = self._attempt_recovery_parse(source_code, syn_err, fn, source_map)

        return tree, diagnostics, source_map

    def _create_syntax_diagnostic(self, syn_err: SyntaxError, filename: str, source_map: SourceMap) -> BugDiagnostic:
        line = syn_err.lineno or 1
        col = (syn_err.offset or 1) - 1
        end_col = col + 1
        if syn_err.text:
            end_col = max(col + 1, min(len(syn_err.text.rstrip()), col + 8))

        span = source_map.get_span(line, col, line, end_col)
        code_line = syn_err.text.rstrip() if syn_err.text else ""

        caret_pad = " " * col
        caret_marks = "~" * max(1, end_col - col)
        overlay = (
            f"L{line}: {code_line}\n"
            f"     {caret_pad}{caret_marks} [CODE-SYN-000: Syntax Error: {syn_err.msg}]"
        )

        style = HighlightStyle(
            color_hex=SEVERITY_PALETTE["CRITICAL"]["hex"],
            underline=SEVERITY_PALETTE["CRITICAL"]["style"],
        )

        trace = [
            CausalStep(
                step_index=1,
                label=f"SyntaxError token encountered: {syn_err.msg}",
                file=filename,
                line=line,
                col=col,
            )
        ]

        # Basic automatic fix heuristics for common syntax errors
        remediation = None
        if syn_err.msg and "expected ':'" in syn_err.msg.lower():
            remediation = AutoRemediation(
                summary="Append missing colon ':' to header statement",
                unified_diff=f"- {code_line}\n+ {code_line}:",
                replacement_code_or_netlist=f"{code_line}:",
                verification_status="SUGGESTED",
            )
        elif syn_err.msg and "unmatched" in syn_err.msg.lower():
            remediation = AutoRemediation(
                summary="Balance unmatched bracket or parenthesis",
                unified_diff=f"- {code_line}\n+ {code_line})",
                replacement_code_or_netlist=code_line,
                verification_status="SUGGESTED",
            )

        return BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-SYN-000",
            severity="CRITICAL",
            message=f"SyntaxError: {syn_err.msg} at line {line}, col {col}",
            scores={"r_total": 1.0, "s_rule": 1.0, "s_ochiai": 1.0, "p_gnn": 1.0},
            code_span=span,
            highlight_style=style,
            causal_trace=trace,
            visual_overlay=overlay,
            auto_remediation=remediation,
        )

    def _attempt_recovery_parse(self, source_code: str, syn_err: SyntaxError,
                                filename: str, source_map: SourceMap) -> Optional[ast.Module]:
        """Attempts parsing by substituting pass on the erroneous line to salvage AST for rest of file."""
        lines = source_code.splitlines()
        bad_line = syn_err.lineno
        if bad_line and 1 <= bad_line <= len(lines):
            recovered_lines = list(lines)
            indent = len(lines[bad_line - 1]) - len(lines[bad_line - 1].lstrip())
            recovered_lines[bad_line - 1] = (" " * indent) + "pass  # syntax recovery"
            try:
                rec_tree = ast.parse("\n".join(recovered_lines), filename=filename)
                indexer = ASTNodeIndexer(source_map)
                indexer.visit(rec_tree)
                rec_tree._indexer = indexer  # type: ignore[attr-defined]
                return rec_tree
            except Exception:
                return None
        return None


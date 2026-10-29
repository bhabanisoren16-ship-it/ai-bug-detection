"""
Stage 1.5: Phase 1 Multi-Layer Visual Highlighting Mechanics.

Implements Stage 1.5 of Phase 1 (Software Code Debugging):
- Layer 1: Exact Token Span Highlight:
  Renders high-contrast background tints and wavy underlines across [start_col, end_col)
  (Crimson #D92D20 for Critical/Error, Amber #F79009 for Warning, Cobalt #0066CC for Info).
- Layer 2: Causal Data-Flow Trail (Backward Slice Badges):
  Visualizes causal dependency chains with numbered step badges:
  e.g. [1. Allocated L15] -> [2. Freed on Error Branch L17] -> [3. Crash L19].
- Layer 3: Ghost-Text Inline Diff Preview:
  Displays verified remediation patches with red strikethrough for defective code
  and green insertion styling for synthesized repairs.
- Outputs standardized formats:
  1. Terminal ANSI colored overlays with caret underlines
  2. Language Server Protocol (LSP) PublishDiagnostics JSON
  3. Interactive HTML snippets for web dashboard rendering

Reference: Section 2 (Stage 1.5) and Figure 2 of the Blueprint.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

from bug_detection.core.schemas import BugDiagnostic, SEVERITY_PALETTE


# ANSI color codes for terminal rendering
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[91m"
ANSI_AMBER = "\033[93m"
ANSI_VIOLET = "\033[95m"
ANSI_BLUE = "\033[94m"
ANSI_GREEN = "\033[92m"
ANSI_BG_RED = "\033[41m\033[37m"


class Phase1Highlighter:
    """
    Multi-layer highlighting renderer for Phase 1 code diagnostics.
    """

    @classmethod
    def render_terminal(cls, diag: BugDiagnostic, source_lines: Optional[List[str]] = None) -> str:
        """
        Renders a diagnostic as an ANSI-colored 3-layer visual overlay for terminals/CLI.
        """
        color = ANSI_RED
        if diag.severity == "WARNING":
            color = ANSI_AMBER
        elif diag.severity == "VIOLET_NET":
            color = ANSI_VIOLET
        elif diag.severity == "INFO":
            color = ANSI_BLUE

        parts: List[str] = []
        r_tot = diag.scores.get("r_total", 0.0)

        # Header badge
        parts.append(
            f"{color}{ANSI_BOLD}[{diag.severity}] {diag.rule_id}{ANSI_RESET} "
            f"(Score R_total={r_tot:.2f}): {diag.message}"
        )

        # Layer 1: Code span with caret underline
        if diag.code_span and source_lines:
            line_idx = diag.code_span.start_line
            if 1 <= line_idx <= len(source_lines):
                src = source_lines[line_idx - 1]
                gutter = f"{line_idx:>4} | "
                parts.append(f"{gutter}{src}")

                c_start = diag.code_span.start_col
                c_end = diag.code_span.end_col
                wavy = "~" * max(1, c_end - c_start)
                pad = " " * (len(gutter) + c_start)
                parts.append(f"{pad}{color}{ANSI_BOLD}{wavy}{ANSI_RESET}")
        elif diag.visual_overlay:
            parts.append(diag.visual_overlay)

        # Layer 2: Causal Trace Badges
        if diag.causal_trace:
            trace_str = " -> ".join(
                f"[Step {s.step_index}: {s.label} (L{s.line})]"
                for s in diag.causal_trace
            )
            parts.append(f"  {ANSI_BOLD}Causal Flow:{ANSI_RESET} {trace_str}")

        # Layer 3: Remediation Diff Preview
        if diag.auto_remediation and diag.auto_remediation.unified_diff:
            parts.append(f"  {ANSI_BOLD}Auto-Fix Suggestion:{ANSI_RESET}")
            for dline in diag.auto_remediation.unified_diff.splitlines():
                if dline.startswith("-"):
                    parts.append(f"    {ANSI_RED}{dline}{ANSI_RESET}")
                elif dline.startswith("+"):
                    parts.append(f"    {ANSI_GREEN}{dline}{ANSI_RESET}")
                else:
                    parts.append(f"    {dline}")

        return "\n".join(parts)

    @classmethod
    def to_lsp_diagnostic(cls, diag: BugDiagnostic) -> Dict[str, Any]:
        """
        Converts a BugDiagnostic into an LSP PublishDiagnostics protocol entry.
        """
        severity_code = 1  # Error
        if diag.severity == "WARNING":
            severity_code = 2  # Warning
        elif diag.severity in ("VIOLET_NET", "INFO"):
            severity_code = 3  # Information

        start_line = 0
        start_col = 0
        end_line = 0
        end_col = 1
        if diag.code_span:
            start_line = max(0, diag.code_span.start_line - 1)
            start_col = max(0, diag.code_span.start_col)
            end_line = max(0, diag.code_span.end_line - 1)
            end_col = max(0, diag.code_span.end_col)

        related = []
        for step in diag.causal_trace:
            related.append({
                "location": {
                    "uri": f"file:///{diag.code_span.file if diag.code_span else 'source.py'}",
                    "range": {
                        "start": {"line": max(0, step.line - 1), "character": max(0, step.col)},
                        "end": {"line": max(0, step.line - 1), "character": max(0, step.col + 5)},
                    },
                },
                "message": f"Step {step.step_index}: {step.label}",
            })

        return {
            "range": {
                "start": {"line": start_line, "character": start_col},
                "end": {"line": end_line, "character": end_col},
            },
            "severity": severity_code,
            "code": diag.rule_id,
            "source": "AI-Bug-Detector",
            "message": diag.message,
            "relatedInformation": related,
            "data": {
                "scores": diag.scores,
                "auto_remediation": diag.auto_remediation.to_dict() if diag.auto_remediation else None,
            },
        }

    @classmethod
    def render_html_code_block(cls, source_code: str, diagnostics: List[BugDiagnostic]) -> str:
        """
        Renders HTML markup of the code with inline span decorations,
        severity highlights, wavy underlines, and tooltips.
        """
        lines = source_code.splitlines()
        # Group diagnostics by line number
        diags_by_line: Dict[int, List[BugDiagnostic]] = {}
        for d in diagnostics:
            if d.code_span:
                ln = d.code_span.start_line
                diags_by_line.setdefault(ln, []).append(d)

        html_lines: List[str] = []
        for idx, line in enumerate(lines, start=1):
            escaped_code = html.escape(line)
            if idx in diags_by_line:
                primary = diags_by_line[idx][0]
                sev = primary.severity
                color = SEVERITY_PALETTE.get(sev, {}).get("hex", "#D92D20")
                style_class = f"bug-line bug-line-{sev.lower()}"

                # Render causal badges if any
                badge_html = ""
                for d in diags_by_line[idx]:
                    badge_html += (
                        f'<div class="bug-inline-card" style="border-left: 3px solid {color}; background: #030407; border: 1px solid #1558C9; padding: 8px 12px; margin-top: 6px; border-radius: 6px;">'
                        f'<span class="bug-badge" style="background: {color}; color: #fff; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 11px;">{d.rule_id}</span> '
                        f'<strong style="color: #f3f4f6;">{html.escape(d.message)}</strong>'
                    )
                    if d.causal_trace:
                        badge_html += '<div class="causal-badges" style="margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap;">'
                        for step in d.causal_trace:
                            badge_html += (
                                f'<span class="causal-step-pill" style="background: #080b13; border: 1px solid #1558C9; padding: 2px 8px; border-radius: 4px; font-size: 11px;">'
                                f'<span class="step-num" style="background: #1558C9; color: #fff; border-radius: 50%; padding: 1px 5px; font-weight: bold;">{step.step_index}</span> {html.escape(step.label)}'
                                f'</span>'
                            )
                        badge_html += '</div>'

                    if d.auto_remediation and d.auto_remediation.unified_diff:
                        badge_html += (
                            f'<div class="diff-preview" style="margin-top: 8px; background: #020305; border: 1px solid #1558C9; border-radius: 4px; padding: 6px 10px;">'
                            f'<div class="diff-title" style="color: #D4FF24; font-weight: 700; font-size: 11px;">Suggested Fix:</div>'
                            f'<pre class="diff-content" style="margin: 0; color: #D4FF24; font-family: monospace; font-size: 11px;">{html.escape(d.auto_remediation.unified_diff)}</pre>'
                            f'</div>'
                        )
                    badge_html += '</div>'

                html_lines.append(
                    f'<div class="{style_class}" data-line="{idx}">'
                    f'<span class="line-gutter">{idx:>4}</span>'
                    f'<span class="code-text" style="text-decoration: underline wavy {color};">{escaped_code}</span>'
                    f'{badge_html}'
                    f'</div>'
                )
            else:
                html_lines.append(
                    f'<div class="code-line" data-line="{idx}">'
                    f'<span class="line-gutter">{idx:>4}</span>'
                    f'<span class="code-text">{escaped_code}</span>'
                    f'</div>'
                )

        return "\n".join(html_lines)


"""
Unified Diagnostic & Highlighting JSON Schema Specification.

Defines the standardized telemetry schema for both Phase 1 (Code) and Phase 2 (Circuit)
diagnostics, following SARIF v2.1.0 conventions with extended highlighting metadata.

Reference: Section 5.1 of the AI & Software Bug Detection Blueprint.
"""

import uuid
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


# ─── Severity & Theme Palette (Section 5.1 & Custom Neon Cyber Theme) ─────────
# Brand & Highlight Colors: #030407 (Obsidian Base), #1558C9 (Cobalt Accent), #D4FF24 (Neon Lime Alert)
THEME_PALETTE = {
    "BASE_OBSIDIAN": "#030407",
    "COBALT_ACCENT": "#1558C9",
    "NEON_LIME":     "#D4FF24",
}

SEVERITY_PALETTE = {
    "CRITICAL":   {"hex": "#D92D20", "style": "wavy-crimson",   "label": "Critical / Error"},
    "WARNING":    {"hex": "#F79009", "style": "dashed-amber",   "label": "Warning"},
    "VIOLET_NET": {"hex": "#7A5AF8", "style": "dotted-violet",  "label": "Violet Net Info"},
    "INFO":       {"hex": "#1558C9", "style": "solid-cobalt",   "label": "Info / Trace"},
    "NEON_AI":    {"hex": "#D4FF24", "style": "glow-neon-lime", "label": "AI Remediation / Patch"},
}


@dataclass
class CodeSpan:
    """Exact token span for highlighting (Section 5.1: code_span)."""
    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    byte_offset_start: int = 0
    byte_offset_end: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CausalStep:
    """One step in the backward-slice causal trace (Section 5.1: causal_trace[])."""
    step_index: int
    label: str
    file: str = ""
    line: int = 0
    col: int = 0
    net_or_var: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CircuitProbe:
    """Circuit-specific probe data for Phase 2 (Section 5.1: circuit_probe)."""
    module: str = ""
    net_names: List[str] = field(default_factory=list)
    gate_instances: List[str] = field(default_factory=list)
    slack_ns: float = 0.0
    clock_domains: List[str] = field(default_factory=list)
    vcd_window_ps: List[int] = field(default_factory=list)
    gdsii_bbox: List[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AutoRemediation:
    """Auto-remediation patch data (Section 5.1: auto_remediation)."""
    summary: str = ""
    unified_diff: str = ""
    replacement_code_or_netlist: str = ""
    verification_status: str = "UNVERIFIED"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HighlightStyle:
    """Visual rendering style for the diagnostic."""
    color_hex: str = "#D92D20"
    underline: str = "wavy-crimson"
    layer: str = ""
    cone: List[str] = field(default_factory=list)
    marker: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v}


@dataclass
class BugDiagnostic:
    """
    Unified Diagnostic & Highlighting Telemetry Record.

    This is the primary data structure emitted by both Phase 1 and Phase 2
    analysis engines. Each diagnostic contains everything needed to:
    1. Identify the bug (rule_id, severity, scores)
    2. Locate it precisely (code_span, circuit_probe)
    3. Visualize it (highlight_style, causal_trace, visual_overlay)
    4. Fix it (auto_remediation)
    """
    # Identity
    bug_id: str = ""
    phase: str = "PHASE_1_CODE"  # "PHASE_1_CODE" | "PHASE_2_CIRCUIT"
    rule_id: str = ""
    severity: str = "WARNING"
    message: str = ""

    # Scoring (Section 4)
    scores: Dict[str, float] = field(default_factory=dict)

    # Location
    code_span: Optional[CodeSpan] = None
    circuit_probe: Optional[CircuitProbe] = None

    # Visualization
    highlight_style: Optional[HighlightStyle] = None
    causal_trace: List[CausalStep] = field(default_factory=list)
    visual_overlay: str = ""

    # Remediation
    auto_remediation: Optional[AutoRemediation] = None

    # Timing metadata
    slack_ns: Optional[float] = None
    detected_at: str = ""

    # David J. Agans 9 Indispensable Rules Mapping
    agans_rule: str = ""
    agans_protocol: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if not self.bug_id:
            # Generate deterministic UUID from artifact path + rule_id + location
            seed = f"{self.phase}:{self.rule_id}:{self.message}"
            if self.code_span:
                seed += f":{self.code_span.file}:{self.code_span.start_line}"
            self.bug_id = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
        if not self.detected_at:
            self.detected_at = datetime.now(timezone.utc).isoformat()
        if not self.highlight_style and self.severity in SEVERITY_PALETTE:
            pal = SEVERITY_PALETTE[self.severity]
            self.highlight_style = HighlightStyle(
                color_hex=pal["hex"], underline=pal["style"]
            )
        if not self.agans_rule and self.rule_id:
            try:
                from bug_detection.core.agans_rules import get_agans_mapping_for_rule
                mapping = get_agans_mapping_for_rule(self.rule_id)
                self.agans_rule = mapping.get("primary_rule", "")
                self.agans_protocol = mapping
            except Exception:
                pass

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        d = {
            "bug_id": self.bug_id,
            "phase": self.phase,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "scores": self.scores,
            "highlight_style": self.highlight_style.to_dict() if self.highlight_style else {},
            "visual_overlay": self.visual_overlay,
            "causal_trace": [s.to_dict() for s in self.causal_trace],
            "detected_at": self.detected_at,
            "agans_rule": self.agans_rule,
            "agans_protocol": self.agans_protocol or {},
        }
        if self.code_span:
            d["code_span"] = self.code_span.to_dict()
            d["line"] = self.code_span.start_line
            d["column"] = self.code_span.start_col
        else:
            d["line"] = 1
            d["column"] = 1

        if self.circuit_probe:
            d["circuit_probe"] = self.circuit_probe.to_dict()
            d["net"] = ", ".join(self.circuit_probe.net_names) if self.circuit_probe.net_names else ""
            d["cross_probe_views"] = {
                "rtl_span": f"{self.circuit_probe.module}.v: {', '.join(self.circuit_probe.gate_instances[:3]) if self.circuit_probe.gate_instances else 'top'}",
                "schematic_net": ", ".join(self.circuit_probe.net_names) if self.circuit_probe.net_names else "N/A",
                "vcd_cursor_window": f"{self.circuit_probe.vcd_window_ps[0] if self.circuit_probe.vcd_window_ps else 10450} ps (Slack={self.slack_ns or 0:.2f}ns)",
                "gdsii_box": self.circuit_probe.gdsii_bbox or [12.4, 45.8, 18.2, 51.0],
            }

        if self.auto_remediation:
            d["auto_remediation"] = self.auto_remediation.to_dict()
            d["patch_diff"] = self.auto_remediation.unified_diff
            d["remediation_advice"] = self.auto_remediation.summary
        else:
            d["patch_diff"] = ""
            d["remediation_advice"] = ""

        d["causal_trail"] = [
            {"step": s.step_index, "desc": s.label, "file": s.file, "line": s.line}
            for s in self.causal_trace
        ]

        # David J. Agans book reference metadata
        primary_info = (self.agans_protocol or {}).get("primary_info", {})
        d["agans_badge"] = primary_info.get("badge_label") or self.agans_rule or "Agans Debugging Rule"
        d["agans_mantra"] = primary_info.get("mantra", "")
        d["agans_summary"] = primary_info.get("summary", "")
        d["agans_rationale"] = (self.agans_protocol or {}).get("rationale", "")
        d["agans_chapter"] = primary_info.get("chapter_number", 0)
        d["agans_remember"] = primary_info.get("book_remember_rules", [])

        if self.slack_ns is not None:
            d["slack_ns"] = self.slack_ns
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class VerificationReport:
    """
    Top-level verification run report aggregating all diagnostics.
    Corresponds to the SARIF v2.1.0 run object.
    """
    run_id: str = ""
    phase1_bugs_highlighted: int = 0
    phase2_bugs_highlighted: int = 0
    status: str = "CLEAN"
    highlights: List[BugDiagnostic] = field(default_factory=list)

    def __post_init__(self):
        if not self.run_id:
            ts = datetime.now(timezone.utc).strftime("%Y-%m%d-%H%M%S")
            self.run_id = f"RUN-{ts}-DUAL-PHASE"

    def add_diagnostic(self, diag: BugDiagnostic):
        self.highlights.append(diag)
        if diag.phase == "PHASE_1_CODE":
            self.phase1_bugs_highlighted += 1
        else:
            self.phase2_bugs_highlighted += 1
        if diag.severity == "CRITICAL":
            self.status = "ACTION_REQUIRED"
        elif self.status == "CLEAN" and diag.severity == "WARNING":
            self.status = "REVIEW_RECOMMENDED"

    def to_dict(self) -> dict:
        return {
            "verification_run_id": self.run_id,
            "summary": {
                "phase1_bugs_highlighted": self.phase1_bugs_highlighted,
                "phase2_bugs_highlighted": self.phase2_bugs_highlighted,
                "status": self.status,
            },
            "highlights": [h.to_dict() for h in self.highlights],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self) -> dict:
        """Export as SARIF v2.1.0 compatible JSON."""
        results = []
        for diag in self.highlights:
            result = {
                "ruleId": diag.rule_id,
                "level": "error" if diag.severity == "CRITICAL" else "warning",
                "message": {"text": diag.message},
                "properties": {
                    "phase": diag.phase,
                    "scores": diag.scores,
                    "severity": diag.severity,
                    "highlight_style": diag.highlight_style.to_dict() if diag.highlight_style else {},
                },
            }
            if diag.code_span:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": diag.code_span.file},
                        "region": {
                            "startLine": diag.code_span.start_line,
                            "startColumn": diag.code_span.start_col + 1,
                            "endLine": diag.code_span.end_line,
                            "endColumn": diag.code_span.end_col + 1,
                        }
                    }
                }]
            if diag.auto_remediation:
                result["fixes"] = [{
                    "description": {"text": diag.auto_remediation.summary},
                    "artifactChanges": [{
                        "description": {"text": diag.auto_remediation.unified_diff}
                    }]
                }]
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "UnifiedBugHighlightEngine",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": results,
            }]
        }


"""
Production Detection Rule & Highlight Signature Catalog.

Defines the 10-rule catalog spanning Phase 1 (CODE-*) and Phase 2 (CIRC-*)
as specified in Section 5.2 of the AI & Software Bug Detection Blueprint.

Each rule contains:
- Canonical ID, phase, bug category
- Formal detection predicate description
- Highlight color hex and severity tier
- Automated fix strategy
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DetectionRule:
    """A single production detection rule from the catalog."""
    rule_id: str
    phase: str                  # "PHASE_1_CODE" | "PHASE_2_CIRCUIT"
    category: str               # Bug category name
    detection_predicate: str    # Formal detection predicate description
    severity: str               # "CRITICAL" | "WARNING" | "VIOLET_NET" | "INFO"
    highlight_hex: str          # Color hex code
    fix_strategy: str           # Automated remediation description
    tags: List[str] = field(default_factory=list)
    agans_rule: str = ""        # Reference to David J. Agans' 9 Indispensable Rules
    agans_summary: str = ""     # Principle rationale from Agans

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "phase": self.phase,
            "category": self.category,
            "detection_predicate": self.detection_predicate,
            "severity": self.severity,
            "highlight_hex": self.highlight_hex,
            "fix_strategy": self.fix_strategy,
            "tags": self.tags,
            "agans_rule": self.agans_rule,
            "agans_summary": self.agans_summary,
        }


# ─── Phase 1: Software Code Detection Rules (Section 5.2) ────────────────────

CODE_MEM_001 = DetectionRule(
    rule_id="CODE-MEM-001",
    phase="PHASE_1_CODE",
    category="Use-After-Free / Double Free",
    detection_predicate=(
        "CFG path exists where state(ptr) == FREED reaches deref(ptr) or free(ptr)."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Nullify pointer or return early after deallocation.",
    tags=["memory", "safety", "use-after-free", "double-free"],
    agans_rule="Rule 6: Keep an Audit Trail",
    agans_summary="Track chronological allocation, free, and dereference events.",
)

CODE_MEM_002 = DetectionRule(
    rule_id="CODE-MEM-002",
    phase="PHASE_1_CODE",
    category="Out-of-Bounds Buffer Write",
    detection_predicate=(
        "SMT solver proves index >= buffer.length or index < 0 "
        "is satisfiable along feasible path."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Insert explicit bounds clamp if (idx >= len).",
    tags=["memory", "safety", "buffer-overflow", "bounds-check"],
    agans_rule="Rule 2: Make It Fail",
    agans_summary="Stimulate boundary-value stress conditions (index >= length).",
)

CODE_NUM_003 = DetectionRule(
    rule_id="CODE-NUM-003",
    phase="PHASE_1_CODE",
    category="Unchecked Division by Zero",
    detection_predicate=(
        "Divisor expression d reaches a / d or a % d "
        "without dominating guard d != 0."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Synthesize zero-divisor guard before operation.",
    tags=["arithmetic", "safety", "division-by-zero"],
    agans_rule="Rule 7: Check the Plug",
    agans_summary="Verify fundamental prerequisites: never assume a divisor is non-zero.",
)

CODE_SEC_004 = DetectionRule(
    rule_id="CODE-SEC-004",
    phase="PHASE_1_CODE",
    category="Unsanitized Taint Sink",
    detection_predicate=(
        "DFG path connects TaintSource(u) to Sink(v) with SanitizerCount == 0."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Replace raw string concat with parameterized API.",
    tags=["security", "taint", "injection", "xss", "sql-injection"],
    agans_rule="Rule 4: Divide and Conquer",
    agans_summary="Slice data flow systematically from untrusted source to sink.",
)

CODE_CON_005 = DetectionRule(
    rule_id="CODE-CON-005",
    phase="PHASE_1_CODE",
    category="Data Race / Missing Lock",
    detection_predicate=(
        "Shared mutable variable accessed by >=2 threads "
        "where LockSet(T1) intersection LockSet(T2) == empty."
    ),
    severity="WARNING",
    highlight_hex="#F79009",
    fix_strategy="Wrap critical section in mutex guard or atomic op.",
    tags=["concurrency", "race-condition", "thread-safety"],
    agans_rule="Rule 8: Get a Fresh View",
    agans_summary="Combine lockset analysis and GNN to spot multi-thread blind spots.",
)


# ─── Phase 2: Circuit / Hardware Detection Rules (Section 5.2) ───────────────

CIRC_STA_001 = DetectionRule(
    rule_id="CIRC-STA-001",
    phase="PHASE_2_CIRCUIT",
    category="Setup / Hold Timing Violation",
    detection_predicate=(
        "Static Timing Analysis computes Slack_setup < 0.0 ns "
        "or Slack_hold < 0.0 ns on path."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Insert pipeline register, resize driver, or buffer delay.",
    tags=["timing", "sta", "setup", "hold", "slack"],
    agans_rule="Rule 3: Quit Thinking and Look",
    agans_summary="Observe actual waveform delay and prove Slack >= 0.0 ns (Rule 9).",
)

CIRC_CDC_002 = DetectionRule(
    rule_id="CIRC-CDC-002",
    phase="PHASE_2_CIRCUIT",
    category="Unsynchronized Clock Crossing",
    detection_predicate=(
        "Arc FF_src(CLK_A) -> FF_dst(CLK_B) where CLK_A != CLK_B "
        "and sync stages < 2."
    ),
    severity="WARNING",
    highlight_hex="#F79009",
    fix_strategy="Instantiate 2-FF synchronizer cell or async Gray FIFO.",
    tags=["cdc", "clock-domain", "metastability", "synchronizer"],
    agans_rule="Rule 1: Understand the System",
    agans_summary="Map asynchronous clock domains and enforce synchronizer contracts.",
)

CIRC_ERC_003 = DetectionRule(
    rule_id="CIRC-ERC-003",
    phase="PHASE_2_CIRCUIT",
    category="Combinational Feedback Loop",
    detection_predicate=(
        "Cycle v_0 -> v_1 -> ... -> v_0 detected in hypergraph "
        "containing zero sequential elements."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Break combinational loop with clocked D-flip-flop.",
    tags=["erc", "feedback-loop", "combinational", "oscillation"],
    agans_rule="Rule 4: Divide and Conquer",
    agans_summary="Isolate oscillating loop with Tarjan's SCC cycle decomposition.",
)

CIRC_ERC_004 = DetectionRule(
    rule_id="CIRC-ERC-004",
    phase="PHASE_2_CIRCUIT",
    category="Floating Net / Multi-Driver",
    detection_predicate=(
        "Net driver count |Drivers(e)| == 0 (undriven) or "
        "|Drivers(e)| > 1 without tri-state mux."
    ),
    severity="VIOLET_NET",
    highlight_hex="#7A5AF8",
    fix_strategy="Tie undriven net to default rail or multiplex drivers.",
    tags=["erc", "floating-net", "multi-driver", "x-propagation"],
    agans_rule="Rule 7: Check the Plug",
    agans_summary="Verify power and driver pins are plugged in before timing analysis.",
)

CIRC_PWR_005 = DetectionRule(
    rule_id="CIRC-PWR-005",
    phase="PHASE_2_CIRCUIT",
    category="SPICE IR-Drop / Latch-Up",
    detection_predicate=(
        "Nodal solver finds V_DD - V_node > 0.05 * V_DD or "
        "substrate current exceeds latch-up limit."
    ),
    severity="CRITICAL",
    highlight_hex="#D92D20",
    fix_strategy="Widen M3/M4 power straps and add decoupling caps.",
    tags=["power", "ir-drop", "latch-up", "spice", "analog"],
    agans_rule="Rule 3: Quit Thinking and Look",
    agans_summary="Observe ground-truth nodal voltages and metal strap widths.",
)


# ─── Catalog Index ────────────────────────────────────────────────────────────

ALL_RULES: Dict[str, DetectionRule] = {
    r.rule_id: r for r in [
        CODE_MEM_001, CODE_MEM_002, CODE_NUM_003, CODE_SEC_004, CODE_CON_005,
        CIRC_STA_001, CIRC_CDC_002, CIRC_ERC_003, CIRC_ERC_004, CIRC_PWR_005,
    ]
}

PHASE1_RULES: Dict[str, DetectionRule] = {
    k: v for k, v in ALL_RULES.items() if v.phase == "PHASE_1_CODE"
}

PHASE2_RULES: Dict[str, DetectionRule] = {
    k: v for k, v in ALL_RULES.items() if v.phase == "PHASE_2_CIRCUIT"
}


def get_rule(rule_id: str) -> DetectionRule:
    """Look up a detection rule by its canonical ID."""
    if rule_id not in ALL_RULES:
        raise KeyError(f"Unknown rule ID: {rule_id}")
    return ALL_RULES[rule_id]


def get_rules_by_severity(severity: str) -> List[DetectionRule]:
    """Return all rules matching a severity tier."""
    return [r for r in ALL_RULES.values() if r.severity == severity]


def get_rules_by_tag(tag: str) -> List[DetectionRule]:
    """Return all rules containing a specific tag."""
    return [r for r in ALL_RULES.values() if tag in r.tags]


"""
Mathematical & Algorithmic Foundations for Bug Scoring.

Implements the five core equations from Section 4 of the Blueprint:
1. Ochiai SBFL Suspiciousness
2. Hybrid AI-Static Priority Score (R_total)
3. Static Timing Setup Slack
4. Static Timing Hold Slack
5. Elmore RC Wire Delay & IR Drop

These formulas quantify fault suspiciousness in software (Phase 1) and
physical timing/electrical margins in circuits (Phase 2).
"""

import math
from dataclasses import dataclass
from typing import Optional


# ─── 1. Ochiai Spectrum-Based Fault Localization (Phase 1) ────────────────────
# Reference: Section 4, Row 1
# S_ochiai(e) = n_ef / sqrt((n_ef + n_nf) * (n_ef + n_ep))
#
# n_ef = number of failing tests that execute statement e
# n_ep = number of passing tests that execute statement e
# n_nf = number of failing tests that do NOT execute statement e

def ochiai_suspiciousness(n_ef: int, n_ep: int, n_nf: int) -> float:
    """
    Compute Ochiai SBFL suspiciousness score for a code statement.

    Args:
        n_ef: Failing tests executing this statement.
        n_ep: Passing tests executing this statement.
        n_nf: Failing tests NOT executing this statement.

    Returns:
        Suspiciousness score in [0.0, 1.0].
        Highlighted when S_ochiai >= 0.65.
    """
    denominator = math.sqrt((n_ef + n_nf) * (n_ef + n_ep))
    if denominator == 0.0:
        return 0.0
    return n_ef / denominator


# ─── 2. Hybrid AI-Static Priority Score (Phase 1 & 2) ────────────────────────
# Reference: Section 4, Row 2
# R_total(e) = 0.35 * S_rule(e) + 0.35 * S_ochiai(e) + 0.30 * P_gnn(bug|e)
#
# S_rule  = Deterministic rule severity score [0,1]
# S_ochiai = Spectrum-based fault localization score [0,1]
# P_gnn   = GNN/LLM root-cause probability [0,1]

# Weight constants (tunable)
W_RULE = 0.35
W_SBFL = 0.35
W_GNN  = 0.30

# Thresholds
THRESHOLD_OCHIAI_HIGHLIGHT = 0.65
THRESHOLD_R_TOTAL_CRITICAL = 0.75


def hybrid_priority_score(
    s_rule: float,
    s_ochiai: float,
    p_gnn: float,
    w_rule: float = W_RULE,
    w_sbfl: float = W_SBFL,
    w_gnn: float = W_GNN,
) -> float:
    """
    Compute hybrid AI-static priority score R_total.

    Combines deterministic rule severity, dynamic spectrum score,
    and GNN/LLM probability. Critical highlight when R_total >= 0.75.

    Args:
        s_rule:  Deterministic rule severity score [0,1].
        s_ochiai: SBFL suspiciousness score [0,1].
        p_gnn:   GNN/LLM root-cause probability [0,1].
        w_rule:  Weight for rule score (default 0.35).
        w_sbfl:  Weight for SBFL score (default 0.35).
        w_gnn:   Weight for GNN score (default 0.30).

    Returns:
        R_total composite score in [0.0, 1.0].
    """
    r = w_rule * s_rule + w_sbfl * s_ochiai + w_gnn * p_gnn
    return min(max(r, 0.0), 1.0)


def severity_from_rule(rule_severity: str) -> float:
    """Convert a rule severity tier to a numeric score [0,1]."""
    mapping = {
        "CRITICAL": 1.0,
        "WARNING": 0.65,
        "VIOLET_NET": 0.45,
        "INFO": 0.25,
    }
    return mapping.get(rule_severity, 0.0)


# ─── 3. Static Timing Setup Slack (Phase 2: Circuit) ─────────────────────────
# Reference: Section 4, Row 3
# Slack_setup = (T_clk + T_cap_clk) - (T_lnch_clk + T_cq + T_comb_max + T_su + T_unc)
#
# Highlighted Amber if 0 <= Slack < 0.15 ns; Crimson if Slack < 0 ns.

@dataclass
class TimingParams:
    """Parameters for static timing analysis slack computation."""
    clk_period_ns: float       # T_clk: Clock period
    cap_clk_delay_ns: float    # T_cap_clk: Capture clock insertion delay
    lnch_clk_delay_ns: float   # T_lnch_clk: Launch clock insertion delay
    clk_to_q_ns: float         # T_cq: Clock-to-Q delay of launch flip-flop
    comb_delay_ns: float       # T_comb: Combinational logic delay (max or min)
    setup_ns: float = 0.0      # T_su: Setup time requirement
    hold_ns: float = 0.0       # T_hold: Hold time requirement
    uncertainty_ns: float = 0.0  # T_unc: Clock uncertainty / jitter


def setup_slack(params: TimingParams) -> float:
    """
    Compute setup timing slack.

    Negative slack means the data path is too slow for the clock period,
    causing a setup timing violation (CIRC-STA-001).
    """
    arrival = params.lnch_clk_delay_ns + params.clk_to_q_ns + params.comb_delay_ns
    required = params.clk_period_ns + params.cap_clk_delay_ns - params.setup_ns - params.uncertainty_ns
    return required - arrival


def hold_slack(params: TimingParams) -> float:
    """
    Compute hold timing slack.

    Negative slack means data changes too quickly after the clock edge,
    potentially corrupting the captured value (CIRC-STA-001 hold violation).

    Slack_hold = (T_lnch_clk + T_cq + T_comb_min) - (T_cap_clk + T_hold + T_unc)
    """
    data_arrival = params.lnch_clk_delay_ns + params.clk_to_q_ns + params.comb_delay_ns
    capture_requirement = params.cap_clk_delay_ns + params.hold_ns + params.uncertainty_ns
    return data_arrival - capture_requirement


def classify_timing_slack(slack_ns: float) -> str:
    """
    Classify timing slack into severity tier.

    Returns:
        'CRITICAL' if slack < 0 ns (timing violation)
        'WARNING' if 0 <= slack < 0.15 ns (tight guardband)
        'INFO' if slack >= 0.15 ns (healthy)
    """
    if slack_ns < 0.0:
        return "CRITICAL"
    elif slack_ns < 0.15:
        return "WARNING"
    return "INFO"


# ─── 5. Elmore RC Wire Delay & IR Drop (Phase 2: Circuit) ────────────────────
# Reference: Section 4, Row 5
# tau_D = sum_i(R_i * C_downstream_i)
# Delta_V = I_branch * R_metal
# Highlighted when Delta_V > 5% * V_DD.

def elmore_delay(segments: list) -> float:
    """
    Compute Elmore RC wire delay.

    Args:
        segments: List of (R_i, C_downstream_i) tuples for each wire segment.

    Returns:
        tau_D delay in nanoseconds.
    """
    return sum(r * c for r, c in segments)


def ir_drop(i_branch: float, r_metal: float) -> float:
    """
    Compute voltage drop across a metal wire segment.

    Args:
        i_branch: Branch current in amps.
        r_metal: Metal resistance in ohms.

    Returns:
        Delta_V voltage drop in volts.
    """
    return i_branch * r_metal


def ir_drop_violation(delta_v: float, v_dd: float, threshold_pct: float = 0.05) -> bool:
    """
    Check if IR drop exceeds the acceptable threshold.

    Default threshold is 5% of V_DD per the blueprint.
    """
    return delta_v > threshold_pct * v_dd


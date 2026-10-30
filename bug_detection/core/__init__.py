"""Core schemas, scoring models, Agans 9 Rules framework, and detection rule catalog."""

from bug_detection.core.schemas import (
    BugDiagnostic,
    CodeSpan,
    CausalStep,
    CircuitProbe,
    HighlightStyle,
    AutoRemediation,
    VerificationReport,
    SEVERITY_PALETTE,
    THEME_PALETTE,
)
from bug_detection.core.rules_catalog import (
    DetectionRule,
    ALL_RULES,
    PHASE1_RULES,
    PHASE2_RULES,
    get_rule,
    get_rules_by_severity,
    get_rules_by_tag,
)
from bug_detection.core.scoring import (
    severity_from_rule,
    ochiai_suspiciousness,
    setup_slack,
    hold_slack,
    classify_timing_slack,
    elmore_delay,
    ir_drop,
    ir_drop_violation,
    hybrid_priority_score,
    TimingParams,
)
from bug_detection.core.agans_rules import (
    AgansRuleId,
    AgansRuleInfo,
    AGANS_NINE_RULES,
    RULE_TO_AGANS_MAPPING,
    get_agans_rule,
    get_agans_mapping_for_rule,
    AgansPreFlightChecker,
    AgansClosedLoopVerifier,
)
from bug_detection.core.pragmatic_programmer import (
    PragmaticPillar,
    PragmaticTip,
    PRAGMATIC_TIPS,
    BrokenWindowItem,
    BrokenWindowsReport,
    ContractViolation,
    TracerBulletResult,
    TracerBulletStage,
    PragmaticAnalyzer,
    get_all_pragmatic_tips,
)

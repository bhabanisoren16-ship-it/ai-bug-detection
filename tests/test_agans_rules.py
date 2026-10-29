"""
Unit tests for David J. Agans' 9 Indispensable Rules for Debugging.

Verifies:
1. Canonical 9 rules definition, mantras, and dual-phase application.
2. Mapping between the 10 production catalog rules and Agans Indispensable Rules.
3. Rule 7: Pre-Flight Sanity Checker ("Check the Plug").
4. Rule 9: Closed-Loop Fix Verifier ("If You Didn't Fix It, It Ain't Fixed").
5. Schema integration: BugDiagnostic auto-inheriting Agans protocol.
"""

import unittest
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
from bug_detection.core.schemas import BugDiagnostic, CodeSpan
from bug_detection.core.rules_catalog import ALL_RULES
from bug_detection.engine import UnifiedBugHighlightEngine


class TestAgansRulesFramework(unittest.TestCase):
    """Test the complete Agans 9 Rules framework."""

    def test_all_nine_rules_exist(self):
        """Verify all 9 rules are formally cataloged with both software and circuit applications."""
        self.assertEqual(len(AGANS_NINE_RULES), 9)

        expected_rules = [
            (AgansRuleId.RULE_1_UNDERSTAND, 1, "Understand the System"),
            (AgansRuleId.RULE_2_MAKE_IT_FAIL, 2, "Make It Fail"),
            (AgansRuleId.RULE_3_QUIT_THINKING_AND_LOOK, 3, "Quit Thinking and Look"),
            (AgansRuleId.RULE_4_DIVIDE_AND_CONQUER, 4, "Divide and Conquer"),
            (AgansRuleId.RULE_5_CHANGE_ONE_THING, 5, "Change One Thing at a Time"),
            (AgansRuleId.RULE_6_KEEP_AUDIT_TRAIL, 6, "Keep an Audit Trail"),
            (AgansRuleId.RULE_7_CHECK_THE_PLUG, 7, "Check the Plug"),
            (AgansRuleId.RULE_8_FRESH_VIEW, 8, "Get a Fresh View"),
            (AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED, 9, "If You Didn't Fix It, It Ain't Fixed"),
        ]

        for rule_id, expected_num, expected_title in expected_rules:
            info = get_agans_rule(rule_id)
            self.assertIsInstance(info, AgansRuleInfo)
            self.assertEqual(info.rule_number, expected_num)
            self.assertEqual(info.title, expected_title)
            self.assertTrue(len(info.mantra) > 10)
            self.assertTrue(len(info.software_application) > 20)
            self.assertTrue(len(info.circuit_application) > 20)

    def test_production_rule_mapping(self):
        """Verify all 10 catalog rules have valid Agans mappings."""
        for rule_id in ALL_RULES:
            mapping = get_agans_mapping_for_rule(rule_id)
            self.assertIn("primary_rule", mapping)
            self.assertIn("primary_info", mapping)
            self.assertIn("contributing_rules", mapping)
            self.assertIn("rationale", mapping)
            self.assertTrue(len(mapping["rationale"]) > 10)

    def test_diagnostic_auto_inherits_agans(self):
        """Verify BugDiagnostic automatically populates Agans telemetry upon initialization."""
        diag = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-NUM-003",
            severity="CRITICAL",
            message="Unchecked division by zero",
            code_span=CodeSpan(file="test.py", start_line=5, start_col=0, end_line=5, end_col=10),
        )

        d = diag.to_dict()
        self.assertIn("agans_rule", d)
        self.assertEqual(d["agans_rule"], AgansRuleId.RULE_7_CHECK_THE_PLUG.value)
        self.assertIn("agans_protocol", d)
        self.assertIn("primary_info", d["agans_protocol"])

    def test_rule_7_check_the_plug_code(self):
        """Test Agans Rule 7: Pre-Flight Sanity Checker on software code."""
        # Test empty code
        empty_issues = AgansPreFlightChecker.check_code_sanity("   ")
        self.assertEqual(len(empty_issues), 1)
        self.assertEqual(empty_issues[0]["agans_rule"], AgansRuleId.RULE_7_CHECK_THE_PLUG.value)

        # Test syntax error
        syntax_issues = AgansPreFlightChecker.check_code_sanity("def broken_syntax(")
        self.assertEqual(len(syntax_issues), 1)
        self.assertIn("Syntax error", syntax_issues[0]["message"])

        # Test literal division by zero
        zero_issues = AgansPreFlightChecker.check_code_sanity("x = 100 / 0")
        self.assertEqual(len(zero_issues), 1)
        self.assertIn("Literal division by zero", zero_issues[0]["message"])

        # Test valid code
        clean_issues = AgansPreFlightChecker.check_code_sanity("x = 100 / 4")
        self.assertEqual(len(clean_issues), 0)

    def test_rule_7_check_the_plug_netlist(self):
        """Test Agans Rule 7: Pre-Flight Sanity Checker on circuit netlists."""
        # Test empty netlist
        empty_issues = AgansPreFlightChecker.check_netlist_sanity({})
        self.assertTrue(len(empty_issues) >= 1)

        # Test disconnected net (no driver)
        bad_netlist = {
            "module": "test_alu",
            "gates": {"G1": {"type": "NAND2"}},
            "nets": {
                "n_floating": {"drivers": [], "sinks": ["G1.A"]},
            },
        }
        net_issues = AgansPreFlightChecker.check_netlist_sanity(bad_netlist)
        self.assertTrue(len(net_issues) >= 1)
        self.assertIn("no power or driver", net_issues[0]["message"])

    def test_rule_9_closed_loop_fix_verification(self):
        """Test Agans Rule 9: If You Didn't Fix It, It Ain't Fixed."""
        engine = UnifiedBugHighlightEngine()
        buggy_code = (
            "def check(val):\n"
            "    if val == None:\n"
            "        return False\n"
            "    return True\n"
        )
        patch = (
            "-     if val == None:\n"
            "+     if val is None:"
        )

        res = engine.verify_remediation_patch(
            source_code=buggy_code,
            target_rule_id="CODE-STYLE-009",
            patch_diff_or_code=patch,
        )

        self.assertEqual(res["agans_rule"], AgansRuleId.RULE_9_NOT_FIXED_AINT_FIXED.value)
        self.assertTrue(res["verified"])
        self.assertEqual(res["status"], "VERIFIED_CLEAN")
        self.assertEqual(res["after_count"], 0)


if __name__ == "__main__":
    unittest.main()


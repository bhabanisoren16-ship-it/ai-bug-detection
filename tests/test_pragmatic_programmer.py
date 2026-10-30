"""
Unit tests for The Pragmatic Programmer engineering principles and automation framework.

Verifies:
1. Canonical Pragmatic Programmer 6 pillars and tips.
2. Broken Windows Index calculation and technical debt entropy levels.
3. Design by Contract (DbC) Precondition, Postcondition, and Invariant verification.
4. Tracer Bullet end-to-end execution slice.
5. ETC (Easier To Change) Refactoring guidance generation.
"""

import unittest
from bug_detection.core.pragmatic_programmer import (
    PragmaticPillar,
    PragmaticTip,
    PRAGMATIC_TIPS,
    PragmaticAnalyzer,
    get_all_pragmatic_tips,
    BrokenWindowsReport,
    ContractViolation,
    TracerBulletResult,
)
from bug_detection.core.schemas import BugDiagnostic, CodeSpan


class TestPragmaticProgrammerFramework(unittest.TestCase):
    """Test the complete Pragmatic Programmer engineering framework."""

    def test_canonical_pillars_and_tips(self):
        """Verify all 6 pillars are defined and tips cover all pillars."""
        self.assertEqual(len(PragmaticPillar), 6)
        tips = get_all_pragmatic_tips()
        self.assertGreaterEqual(len(tips), 10)

        pillars_found = {t["pillar"] for t in tips}
        for p in PragmaticPillar:
            self.assertIn(p.value, pillars_found, f"Pillar {p.value} missing tips")

    def test_broken_windows_pristine_code(self):
        """Zero defects should yield Pristine A+ rating with 0 Broken Windows score."""
        report = PragmaticAnalyzer.compute_broken_windows([], source_code="def clean(): pass")
        self.assertIsInstance(report, BrokenWindowsReport)
        self.assertEqual(report.total_score, 0)
        self.assertEqual(report.entropy_level, "PRISTINE")
        self.assertEqual(report.clean_code_rating, "A+")
        self.assertEqual(report.windows_count, 0)

    def test_broken_windows_decay_detection(self):
        """Multiple defects should increase Broken Windows Index."""
        diag1 = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-NUM-003",
            severity="CRITICAL",
            message="Unchecked division by zero",
            code_span=CodeSpan(file="calc.py", start_line=10, start_col=0, end_line=10, end_col=15),
        )
        diag2 = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-MEM-001",
            severity="CRITICAL",
            message="Use-After-Free detected on packet buffer",
            code_span=CodeSpan(file="calc.py", start_line=25, start_col=0, end_line=25, end_col=10),
        )

        code_with_bare_except = "try:\n    x = 1\nexcept:\n    pass\n"
        report = PragmaticAnalyzer.compute_broken_windows([diag1, diag2], source_code=code_with_bare_except)

        self.assertGreater(report.total_score, 30)
        self.assertIn(report.entropy_level, ["ELEVATED_DECAY", "CRITICAL_ROT"])
        self.assertGreaterEqual(report.windows_count, 3)

        # Check clean code tips on windows
        tips = [w.clean_code_tip for w in report.windows]
        self.assertTrue(any("Tip 37" in t for t in tips))
        self.assertTrue(any("Tip 3" in t for t in tips))

    def test_design_by_contract_inspector(self):
        """Verify Precondition, Postcondition, and Invariant contract violations are detected."""
        diag_num = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-NUM-003",
            severity="CRITICAL",
            message="Division by zero",
        )
        diag_mem = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-MEM-001",
            severity="CRITICAL",
            message="Use-After-Free",
        )
        diag_sta = BugDiagnostic(
            phase="PHASE_2_CIRCUIT",
            rule_id="CIRC-STA-001",
            severity="CRITICAL",
            message="Setup slack violation -0.42 ns",
        )

        violations = PragmaticAnalyzer.inspect_contracts("x / 0", [diag_num, diag_mem, diag_sta])
        self.assertEqual(len(violations), 3)

        types = {v.contract_type for v in violations}
        self.assertIn("PRECONDITION", types)
        self.assertIn("INVARIANT", types)
        self.assertIn("POSTCONDITION", types)

        # Precondition fault belongs to caller
        pre = next(v for v in violations if v.contract_type == "PRECONDITION")
        self.assertEqual(pre.fault_party, "CALLER")
        self.assertIn("require", pre.formal_clause)

    def test_tracer_bullet_execution(self):
        """Verify tracer bullet executes end-to-end stages."""
        code = "def process(x):\n    return x + 1\n"
        result = PragmaticAnalyzer.run_tracer_bullet(code)
        self.assertIsInstance(result, TracerBulletResult)
        self.assertTrue(result.success)
        self.assertTrue(result.target_hit)
        self.assertGreater(len(result.stages), 2)
        self.assertEqual(result.stages[0].status, "PASS")

    def test_tracer_bullet_syntax_fail(self):
        """Syntax error should immediately halt tracer bullet."""
        bad_code = "def syntax_err(:"
        result = PragmaticAnalyzer.run_tracer_bullet(bad_code)
        self.assertFalse(result.success)
        self.assertFalse(result.target_hit)
        self.assertEqual(result.stages[0].status, "FAIL")

    def test_etc_refactoring_advice(self):
        """Verify ETC refactoring blueprints are generated."""
        diag = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-NUM-003",
            severity="CRITICAL",
            message="Division by zero",
        )
        advice = PragmaticAnalyzer.get_refactoring_advice([diag])
        self.assertEqual(len(advice), 1)
        self.assertIn("ETC", advice[0]["principle"])
        self.assertIn("step_1", advice[0])
        self.assertIn("step_2", advice[0])
        self.assertIn("step_3", advice[0])


if __name__ == "__main__":
    unittest.main()


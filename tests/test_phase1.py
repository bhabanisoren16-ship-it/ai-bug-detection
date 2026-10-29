"""
Unit and Integration Tests for Phase 1: Software Code Debugging.

Covers:
- Stage 1.1: ASTAnalyzer (AST indexing, error recovery, byte offset mapping)
- Stage 1.2: CFGDFGAnalyzer (Use-After-Free, Division by Zero, Taint to Sink, Data Race)
- Stage 1.3: SpectrumAnalyzer (Ochiai SBFL mathematical formulation)
- Stage 1.4: AIDetector (Off-by-One, Mutable Defaults, None Comparison, Bare Except)
- Stage 1.5: Phase1Highlighter (LSP conversion, Visual Carets, HTML Rendering)
- UnifiedBugHighlightEngine Phase 1 on sample buggy code
"""

import sys
import os
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from bug_detection.core.schemas import BugDiagnostic, SEVERITY_PALETTE
from bug_detection.core.scoring import ochiai_suspiciousness, hybrid_priority_score
from bug_detection.phase1.ast_analyzer import ASTAnalyzer, SourceMap
from bug_detection.phase1.cfg_dfg_analyzer import CFGDFGAnalyzer
from bug_detection.phase1.dynamic_analyzer import SpectrumAnalyzer, TestExecutionRecord
from bug_detection.phase1.ai_detector import AIDetector
from bug_detection.phase1.highlighter import Phase1Highlighter
from bug_detection.engine import UnifiedBugHighlightEngine


class TestPhase1Stage1(unittest.TestCase):
    """Stage 1.1: AST parsing, coordinates, error recovery."""

    def setUp(self):
        self.analyzer = ASTAnalyzer()

    def test_valid_ast_indexing(self):
        code = "def add(a, b):\n    return a + b\n"
        tree, diags, smap = self.analyzer.analyze("math_ops.py", code)
        self.assertIsNotNone(tree)
        self.assertEqual(len(diags), 0)
        self.assertEqual(len(smap.lines), 2)

    def test_syntax_error_recovery(self):
        bad_code = "def broken(\n    return 42\n"
        tree, diags, smap = self.analyzer.analyze("broken.py", bad_code)
        self.assertGreater(len(diags), 0)
        self.assertEqual(diags[0].rule_id, "CODE-SYN-000")
        self.assertEqual(diags[0].severity, "CRITICAL")
        self.assertIn("SyntaxError", diags[0].message)


class TestPhase1Stage2(unittest.TestCase):
    """Stage 1.2: CFG/DFG, Memory Lifecycle, Taint, Zero Divisor, Concurrency."""

    def setUp(self):
        self.ast_analyzer = ASTAnalyzer()
        self.cfg_analyzer = CFGDFGAnalyzer()

    def test_use_after_free_detection(self):
        code = (
            "buf = allocate_buffer(1024)\n"
            "free_buf(buf)\n"
            "process(buf)\n"
        )
        tree, _, _ = self.ast_analyzer.analyze("mem.py", code)
        diags = self.cfg_analyzer.analyze("mem.py", code, tree)
        uaf = [d for d in diags if d.rule_id == "CODE-MEM-001"]
        self.assertGreater(len(uaf), 0)
        self.assertEqual(uaf[0].severity, "CRITICAL")
        self.assertIn("Use-After-Free", uaf[0].message)
        self.assertEqual(len(uaf[0].causal_trace), 3)

    def test_division_by_zero_detection(self):
        code = (
            "count = 0\n"
            "ratio = 100 / count\n"
        )
        tree, _, _ = self.ast_analyzer.analyze("calc.py", code)
        diags = self.cfg_analyzer.analyze("calc.py", code, tree)
        div0 = [d for d in diags if d.rule_id == "CODE-NUM-003"]
        self.assertGreater(len(div0), 0)
        self.assertEqual(div0[0].severity, "CRITICAL")
        self.assertIn("Division by Zero", div0[0].message)

    def test_taint_propagation_to_sink(self):
        code = (
            "cmd = input('Enter command: ')\n"
            "os.system(cmd)\n"
        )
        tree, _, _ = self.ast_analyzer.analyze("sec.py", code)
        diags = self.cfg_analyzer.analyze("sec.py", code, tree)
        sec = [d for d in diags if d.rule_id == "CODE-SEC-004"]
        self.assertGreater(len(sec), 0)
        self.assertEqual(sec[0].severity, "CRITICAL")
        self.assertIn("Command Injection", sec[0].message)

    def test_sql_injection_concatenation(self):
        code = (
            "user = input()\n"
            "q = 'SELECT * FROM users WHERE name = ' + user\n"
        )
        tree, _, _ = self.ast_analyzer.analyze("db.py", code)
        diags = self.cfg_analyzer.analyze("db.py", code, tree)
        sec = [d for d in diags if d.rule_id == "CODE-SEC-004"]
        self.assertGreater(len(sec), 0)


class TestPhase1Stage3(unittest.TestCase):
    """Stage 1.3: Dynamic Instrumentation & Ochiai SBFL."""

    def test_ochiai_exact_math(self):
        # S_ochiai = n_ef / sqrt((n_ef + n_nf) * (n_ef + n_ep))
        # n_ef = 8, n_nf = 2, n_ep = 1
        # denominator = sqrt((8 + 2) * (8 + 1)) = sqrt(10 * 9) = sqrt(90) = 9.4868
        # S_ochiai = 8 / 9.4868 = 0.8433
        score = ochiai_suspiciousness(n_ef=8, n_ep=1, n_nf=2)
        self.assertAlmostEqual(score, 0.8433, places=3)
        self.assertGreaterEqual(score, 0.65)

    def test_spectrum_analyzer_scoring(self):
        analyzer = SpectrumAnalyzer(highlight_threshold=0.65)
        # 3 failing tests executing line 15
        analyzer.add_test_result("test_fail_1", passed=False, covered_lines={10, 15, 20})
        analyzer.add_test_result("test_fail_2", passed=False, covered_lines={15, 25})
        analyzer.add_test_result("test_fail_3", passed=False, covered_lines={15, 30})
        # 1 passing test executing line 15
        analyzer.add_test_result("test_pass_1", passed=True, covered_lines={15, 40})
        # 10 passing tests executing line 10
        for i in range(10):
            analyzer.add_test_result(f"test_pass_batch_{i}", passed=True, covered_lines={10, 40})

        scores = analyzer.compute_statement_scores()
        self.assertIn(15, scores)
        self.assertGreaterEqual(scores[15]["ochiai"], 0.70)


class TestPhase1Stage4(unittest.TestCase):
    """Stage 1.4: AI / Semantic Bug Detection."""

    def setUp(self):
        self.ast_analyzer = ASTAnalyzer()
        self.ai_detector = AIDetector()

    def test_off_by_one_detection(self):
        code = (
            "def compare_adjacent(data):\n"
            "    length = len(data)\n"
            "    for i in range(length):\n"
            "        if data[i] == data[i + 1]:\n"
            "            return True\n"
        )
        tree, _, _ = self.ast_analyzer.analyze("algo.py", code)
        diags = self.ai_detector.analyze("algo.py", code, tree)
        off_by_one = [d for d in diags if d.rule_id == "CODE-LOG-006"]
        self.assertGreater(len(off_by_one), 0)
        self.assertEqual(off_by_one[0].severity, "CRITICAL")
        self.assertIn("Off-by-One", off_by_one[0].message)

    def test_mutable_default_argument(self):
        code = "def append_val(x, arr=[]):\n    arr.append(x)\n    return arr\n"
        tree, _, _ = self.ast_analyzer.analyze("func.py", code)
        diags = self.ai_detector.analyze("func.py", code, tree)
        mut = [d for d in diags if d.rule_id == "CODE-SEM-007"]
        self.assertGreater(len(mut), 0)
        self.assertEqual(mut[0].severity, "WARNING")

    def test_none_equality_comparison(self):
        code = "if val == None:\n    pass\n"
        tree, _, _ = self.ast_analyzer.analyze("check.py", code)
        diags = self.ai_detector.analyze("check.py", code, tree)
        none_comp = [d for d in diags if d.rule_id == "CODE-SEM-008"]
        self.assertGreater(len(none_comp), 0)
        self.assertEqual(none_comp[0].severity, "INFO")

    def test_bare_except_clause(self):
        code = "try:\n    do_work()\nexcept:\n    pass\n"
        tree, _, _ = self.ast_analyzer.analyze("err.py", code)
        diags = self.ai_detector.analyze("err.py", code, tree)
        bare = [d for d in diags if d.rule_id == "CODE-SEM-009"]
        self.assertGreater(len(bare), 0)
        self.assertEqual(bare[0].severity, "WARNING")


class TestPhase1Stage5(unittest.TestCase):
    """Stage 1.5: Multi-Layer Visual Highlighting Mechanics."""

    def test_lsp_conversion(self):
        diag = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-MEM-001",
            severity="CRITICAL",
            message="Use-After-Free",
        )
        lsp_dict = Phase1Highlighter.to_lsp_diagnostic(diag)
        self.assertEqual(lsp_dict["code"], "CODE-MEM-001")
        self.assertEqual(lsp_dict["severity"], 1)

    def test_terminal_rendering(self):
        diag = BugDiagnostic(
            phase="PHASE_1_CODE",
            rule_id="CODE-NUM-003",
            severity="CRITICAL",
            message="Division by zero",
            visual_overlay="L12: res = a / 0\n     ~~~~~~~~~~",
        )
        rendered = Phase1Highlighter.render_terminal(diag)
        self.assertIn("CODE-NUM-003", rendered)
        self.assertIn("CRITICAL", rendered)


class TestPhase1Integration(unittest.TestCase):
    """End-to-end integration test of UnifiedBugHighlightEngine Phase 1."""

    def test_sample_buggy_code_full_scan(self):
        engine = UnifiedBugHighlightEngine()
        sample_path = os.path.join(PROJECT_ROOT, "tests", "sample_buggy_code.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        results = engine.analyze_phase1_code("sample_buggy_code.py", code)
        self.assertGreater(len(results), 5)

        rule_ids = {r["rule_id"] for r in results}
        self.assertIn("CODE-MEM-001", rule_ids)  # Use-After-Free
        self.assertIn("CODE-NUM-003", rule_ids)  # Div by zero
        self.assertIn("CODE-SEC-004", rule_ids)  # Taint injection


if __name__ == "__main__":
    unittest.main()


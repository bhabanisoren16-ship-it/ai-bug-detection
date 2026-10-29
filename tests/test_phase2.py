"""
Unit and Integration Tests for Phase 2: Hardware & Circuit Debugging.

Covers:
- Stage 2.1: NetlistParser & CircuitGraph Extraction
- Stage 2.2: ERCAnalyzer, CDCAnalyzer, STAAnalyzer
- Stage 2.3: FormalChecker (BMC & X-propagation)
- Stage 2.4: GNNFaultLocator (Fault probabilities & IR-drop)
- Stage 2.5: CrossProbeHighlighter (Synchronized 4-View Visualizer)
- UnifiedBugHighlightEngine Phase 2 on sample netlist
"""

import sys
import os
import json
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from bug_detection.core.scoring import (
    TimingParams,
    setup_slack,
    hold_slack,
    classify_timing_slack,
    ir_drop,
    ir_drop_violation,
)
from bug_detection.phase2.netlist_parser import NetlistParser, CircuitGraph
from bug_detection.phase2.erc_cdc_sta import ERCAnalyzer, CDCAnalyzer, STAAnalyzer
from bug_detection.phase2.formal_checker import FormalChecker
from bug_detection.phase2.gnn_fault_locator import GNNFaultLocator, PowerNode
from bug_detection.phase2.cross_probe import CrossProbeHighlighter
from bug_detection.engine import UnifiedBugHighlightEngine


class TestPhase2Stage1(unittest.TestCase):
    """Stage 2.1: HDL Netlist elaboration into directed hypergraph."""

    def test_netlist_parsing(self):
        sample_dict = {
            "module": "alu_test",
            "gates": [
                {"id": "FF1", "type": "DFF", "clock_domain": "CLK_A", "delay_ns": 0.0},
                {"id": "G1", "type": "AND", "clock_domain": "CLK_A", "delay_ns": 0.2},
                {"id": "FF2", "type": "DFF", "clock_domain": "CLK_A", "delay_ns": 0.0},
            ],
            "nets": [
                {"name": "n1", "drivers": ["FF1"], "sinks": ["G1"]},
                {"name": "n2", "drivers": ["G1"], "sinks": ["FF2"]},
            ]
        }
        graph = NetlistParser.parse(sample_dict)
        self.assertEqual(graph.design_name, "alu_test")
        self.assertEqual(len(graph.gates), 3)
        self.assertEqual(len(graph.nets), 2)
        self.assertEqual(len(graph.sequential_gates()), 2)
        self.assertEqual(len(graph.combinational_gates()), 1)


class TestPhase2Stage2(unittest.TestCase):
    """Stage 2.2: Structural ERC, CDC, and Static Timing Analysis (STA)."""

    def test_sta_setup_slack_calculation(self):
        # Slack_setup = (T_clk + T_cap_clk) - (T_lnch_clk + T_cq + T_comb_max + T_su + T_unc)
        # T_clk = 2.0 ns, T_cap_clk = 0.15 ns
        # Required = 2.0 + 0.15 - 0.12 - 0.05 = 1.98 ns
        # T_lnch_clk = 0.10 ns, T_cq = 0.18 ns, T_comb = 2.12 ns
        # Arrival = 0.10 + 0.18 + 2.12 = 2.40 ns
        # Slack = 1.98 - 2.40 = -0.42 ns (< 0 -> CRITICAL violation)
        params = TimingParams(
            clk_period_ns=2.0,
            cap_clk_delay_ns=0.15,
            lnch_clk_delay_ns=0.10,
            clk_to_q_ns=0.18,
            comb_delay_ns=2.12,
            setup_ns=0.12,
            uncertainty_ns=0.05,
        )
        slack = setup_slack(params)
        self.assertAlmostEqual(slack, -0.42, places=2)
        self.assertEqual(classify_timing_slack(slack), "CRITICAL")

    def test_erc_floating_net_detection(self):
        sample = {
            "module": "floating_test",
            "gates": [{"id": "G1", "type": "AND"}],
            "nets": [{"name": "n_float", "drivers": [], "sinks": ["G1"]}]
        }
        graph = NetlistParser.parse(sample)
        diags = ERCAnalyzer().analyze(graph)
        floating = [d for d in diags if d.rule_id == "CIRC-ERC-004"]
        self.assertGreater(len(floating), 0)
        self.assertEqual(floating[0].severity, "VIOLET_NET")

    def test_cdc_asynchronous_crossing_detection(self):
        sample = {
            "module": "cdc_test",
            "gates": [
                {"id": "FF_A", "type": "DFF", "clock_domain": "CLK_FAST"},
                {"id": "FF_B", "type": "DFF", "clock_domain": "CLK_SLOW"},
            ],
            "nets": [{"name": "cross_net", "drivers": ["FF_A"], "sinks": ["FF_B"]}],
            "timing_paths": [{
                "launch_ff": "FF_A",
                "capture_ff": "FF_B",
                "crossing_net": "cross_net",
                "comb_cone": [],
            }]
        }
        graph = NetlistParser.parse(sample)
        diags = CDCAnalyzer().analyze(graph)
        cdc = [d for d in diags if d.rule_id == "CIRC-CDC-002"]
        self.assertGreater(len(cdc), 0)
        self.assertEqual(cdc[0].severity, "WARNING")


class TestPhase2Stage3(unittest.TestCase):
    """Stage 2.3: Formal SMT BMC & Waveform X-propagation."""

    def test_x_propagation_trace(self):
        sample = {
            "module": "x_test",
            "gates": [{"id": "G1", "type": "OR"}, {"id": "G2", "type": "BUF"}],
            "nets": [
                {"name": "undriven_net", "drivers": [], "sinks": ["G1"]},
                {"name": "n_out", "drivers": ["G1"], "sinks": ["G2"]},
            ]
        }
        graph = NetlistParser.parse(sample)
        checker = FormalChecker(design_name="x_test")
        diags = checker.trace_x_propagation(graph, failing_net_names=["undriven_net"])
        self.assertGreater(len(diags), 0)
        self.assertEqual(diags[0].severity, "VIOLET_NET")
        self.assertIn("X-Propagation", diags[0].message)


class TestPhase2Stage4(unittest.TestCase):
    """Stage 2.4: GNN Fault Localization & Analog IR-Drop."""

    def test_ir_drop_hotspot_detection(self):
        # V_DD = 1.0 V, drop = 85 mV (8.5% > 5%)
        v_dd = 1.0
        delta_v = ir_drop(i_branch=0.015, r_metal=5.7) # 15mA * 5.7 ohms = 0.0855 V
        self.assertTrue(ir_drop_violation(delta_v=delta_v, v_dd=v_dd, threshold_pct=0.05))

        locator = GNNFaultLocator(design_name="power_core")
        diags = locator.analyze_ir_drop(v_dd=1.0)
        pwr = [d for d in diags if d.rule_id == "CIRC-PWR-005"]
        self.assertGreater(len(pwr), 0)
        self.assertEqual(pwr[0].severity, "CRITICAL")
        self.assertIn("IR-Drop", pwr[0].message)

    def test_gnn_fault_probability_ranking(self):
        sample = {
            "module": "gnn_test",
            "gates": [
                {"id": "FF1", "type": "DFF", "delay_ns": 0.0},
                {"id": "CARRY_CRIT", "type": "CARRY", "delay_ns": 0.45, "fan_out": 4},
                {"id": "FF_OUT", "type": "DFF", "delay_ns": 0.0},
            ],
            "nets": [
                {"name": "n1", "drivers": ["FF1"], "sinks": ["CARRY_CRIT"]},
                {"name": "n2", "drivers": ["CARRY_CRIT"], "sinks": ["FF_OUT"]},
            ]
        }
        graph = NetlistParser.parse(sample)
        locator = GNNFaultLocator(design_name="gnn_test")
        diags = locator.localize_faults(graph, failing_outputs=["FF_OUT"])
        self.assertGreater(len(diags), 0)
        self.assertEqual(diags[0].rule_id, "CIRC-GNN-001")


class TestPhase2Stage5(unittest.TestCase):
    """Stage 2.5: Synchronized 4-View Cross-Probe Highlighting."""

    def test_cross_probe_views_generation(self):
        from bug_detection.core.schemas import BugDiagnostic, CircuitProbe, HighlightStyle

        diag = BugDiagnostic(
            phase="PHASE_2_CIRCUIT",
            rule_id="CIRC-STA-001",
            severity="CRITICAL",
            circuit_probe=CircuitProbe(
                module="alu",
                net_names=["alu_carry_n7"],
                gate_instances=["FF_Launch", "CARRY8_U4", "FF_Capture"],
                slack_ns=-0.420,
                vcd_window_ps=[18420, 18980],
                gdsii_bbox=["M3", 142.4, 88.0, 219.6, 104.2],
            ),
            highlight_style=HighlightStyle(color_hex="#D92D20"),
        )
        views = CrossProbeHighlighter.generate_views(diag)
        self.assertIsNotNone(views.view1_rtl)
        self.assertIsNotNone(views.view2_schematic)
        self.assertIsNotNone(views.view3_waveform)
        self.assertIsNotNone(views.view4_layout)
        self.assertEqual(views.view4_layout.metal_layer, "M3")


class TestPhase2Integration(unittest.TestCase):
    """Integration test with UnifiedBugHighlightEngine on sample netlist."""

    def test_sample_netlist_analysis(self):
        engine = UnifiedBugHighlightEngine()
        netlist_path = os.path.join(PROJECT_ROOT, "tests", "sample_netlist.json")
        with open(netlist_path, "r", encoding="utf-8") as f:
            netlist = json.load(f)

        results = engine.analyze_phase2_circuit(netlist)
        self.assertGreater(len(results), 0)
        rule_ids = {r["rule_id"] for r in results}
        self.assertTrue("CIRC-STA-001" in rule_ids or "CIRC-ERC-004" in rule_ids)


if __name__ == "__main__":
    unittest.main()


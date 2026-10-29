"""
Phase 2: Hardware Circuit Debugging — 5-Stage Netlist & STA Workflow.

Stage 2.1: NetlistParser, CircuitGraph — HDL elaboration & hypergraph extraction
Stage 2.2: ERCAnalyzer, CDCAnalyzer, STAAnalyzer — Structural ERC, CDC, and Static Timing Analysis
Stage 2.3: FormalChecker — Bounded Model Checking (BMC) & X-propagation tracing
Stage 2.4: GNNFaultLocator — AI/GNN fault localization & analog IR-drop analysis
Stage 2.5: CrossProbeHighlighter — Synchronized 4-view cross-probe highlighting engine
"""

from bug_detection.phase2.netlist_parser import (
    CircuitGraph,
    GateVertex,
    NetEdge,
    NetPin,
    NetlistParser,
    TimingPath,
)
from bug_detection.phase2.erc_cdc_sta import (
    CDCAnalyzer,
    ERCAnalyzer,
    STAAnalyzer,
)
from bug_detection.phase2.formal_checker import (
    AssertionProperty,
    FormalChecker,
)
from bug_detection.phase2.gnn_fault_locator import (
    GNNFaultLocator,
    PowerNode,
)
from bug_detection.phase2.cross_probe import (
    CrossProbeHighlighter,
    CrossProbePayload,
)

__all__ = [
    "NetlistParser",
    "CircuitGraph",
    "GateVertex",
    "NetEdge",
    "NetPin",
    "TimingPath",
    "ERCAnalyzer",
    "CDCAnalyzer",
    "STAAnalyzer",
    "FormalChecker",
    "AssertionProperty",
    "GNNFaultLocator",
    "PowerNode",
    "CrossProbeHighlighter",
    "CrossProbePayload",
]

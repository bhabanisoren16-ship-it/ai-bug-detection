"""
Stage 2.2 — Structural ERC, CDC & STA Analysis.

Three complementary structural analyzers that operate on the
:class:`~bug_detection.phase2.netlist_parser.CircuitGraph` hypergraph
produced by Stage 2.1 and emit :class:`~bug_detection.core.schemas.BugDiagnostic`
records for every violation found.

Analyzers
---------
* **ERCAnalyzer**  — Electrical Rule Checking
    - Combinational feedback loops via Tarjan's SCC algorithm (CIRC-ERC-003)
    - Undriven / floating nets where ``|Drivers(e)| == 0`` (CIRC-ERC-004)
    - Multi-driver bus contention ``|Drivers(e)| > 1`` without tri-state (CIRC-ERC-004)
    - Excessive capacitive fan-out beyond threshold

* **CDCAnalyzer**  — Clock Domain Crossing
    - Trace clock trees from root sources to sequential elements
    - Flag arcs ``FF_A(CLK_A) → FF_B(CLK_B)`` without 2-FF synchronizer (CIRC-CDC-002)

* **STAAnalyzer**  — Static Timing Analysis
    - Forward arrival-time propagation, backward required-time propagation
    - Setup and hold slack via :func:`~bug_detection.core.scoring.setup_slack` /
      :func:`~bug_detection.core.scoring.hold_slack`
    - Negative-slack paths flagged as CIRC-STA-001

Reference: Section 3.2, 4 & 5.2 of the AI & Software Bug Detection Blueprint.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..core.schemas import (
    BugDiagnostic,
    CausalStep,
    CircuitProbe,
    CodeSpan,
    HighlightStyle,
    SEVERITY_PALETTE,
)
from ..core.scoring import (
    TimingParams,
    classify_timing_slack,
    hold_slack,
    setup_slack,
)
from ..core.rules_catalog import (
    CIRC_CDC_002,
    CIRC_ERC_003,
    CIRC_ERC_004,
    CIRC_STA_001,
)
from .netlist_parser import CircuitGraph, GateVertex, SEQUENTIAL_GATE_TYPES


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ERC Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class ERCAnalyzer:
    """Electrical Rule Checking on the circuit hypergraph.

    Detects:
        1. Combinational feedback loops (Tarjan SCC on the combinational-only
           sub-graph) — CIRC-ERC-003.
        2. Undriven / floating nets — CIRC-ERC-004.
        3. Multi-driver contention (no tri-state) — CIRC-ERC-004.
        4. Excessive capacitive fan-out (configurable threshold).

    Usage::

        analyzer = ERCAnalyzer(max_fan_out=64)
        diagnostics = analyzer.analyze(graph)
    """

    def __init__(self, max_fan_out: int = 64) -> None:
        self.max_fan_out = max_fan_out

    def analyze(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Run all ERC checks and return aggregated diagnostics.

        Args:
            graph: Parsed :class:`CircuitGraph` from Stage 2.1.

        Returns:
            List of :class:`BugDiagnostic` records for every violation.
        """
        diags: List[BugDiagnostic] = []
        diags.extend(self._check_combinational_loops(graph))
        diags.extend(self._check_floating_nets(graph))
        diags.extend(self._check_multi_driver(graph))
        diags.extend(self._check_fan_out(graph))
        return diags

    # ── Tarjan SCC for combinational feedback loops ───────────────────────────

    def _check_combinational_loops(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Detect combinational feedback loops using Tarjan's SCC algorithm.

        Only the combinational sub-graph is considered: edges traversing
        sequential elements (DFF, LATCH, SRAM) are **not** followed, so
        legitimate pipeline feedback through registers is ignored.
        """
        # Build combinational-only adjacency
        comb_ids = {
            gid for gid, g in graph.gates.items()
            if g.gate_type not in SEQUENTIAL_GATE_TYPES
        }
        comb_adj: Dict[str, List[str]] = {
            gid: [
                succ for succ in graph.adjacency.get(gid, set())
                if succ in comb_ids
            ]
            for gid in comb_ids
        }

        sccs = self._tarjan_scc(comb_adj)
        diags: List[BugDiagnostic] = []

        for scc in sccs:
            if len(scc) < 2:
                continue  # single-node SCC, not a loop

            gate_instances = list(scc)
            loop_gates = [graph.gates[gid] for gid in gate_instances if gid in graph.gates]
            causal_trace = [
                CausalStep(
                    step_index=i,
                    label=f"Loop node: {g.instance_id} ({g.gate_type})",
                    file=g.rtl_file,
                    line=g.rtl_line,
                    net_or_var=g.instance_id,
                )
                for i, g in enumerate(loop_gates)
            ]

            first_gate = loop_gates[0] if loop_gates else None
            code_span = None
            if first_gate and first_gate.rtl_file:
                code_span = CodeSpan(
                    file=first_gate.rtl_file,
                    start_line=first_gate.rtl_line,
                    start_col=0,
                    end_line=first_gate.rtl_line,
                    end_col=0,
                )

            diag = BugDiagnostic(
                phase="PHASE_2_CIRCUIT",
                rule_id=CIRC_ERC_003.rule_id,
                severity=CIRC_ERC_003.severity,
                message=(
                    f"Combinational feedback loop detected among "
                    f"{len(scc)} gates: {', '.join(gate_instances[:5])}"
                    f"{'...' if len(gate_instances) > 5 else ''}"
                ),
                code_span=code_span,
                circuit_probe=CircuitProbe(
                    gate_instances=gate_instances,
                    net_names=[],
                ),
                highlight_style=HighlightStyle(
                    color_hex=CIRC_ERC_003.highlight_hex,
                    underline="wavy-crimson",
                    cone=gate_instances,
                ),
                causal_trace=causal_trace,
            )
            diags.append(diag)

        return diags

    @staticmethod
    def _tarjan_scc(adj: Dict[str, List[str]]) -> List[Set[str]]:
        """Tarjan's strongly-connected-components algorithm.

        Args:
            adj: Adjacency list ``{node: [successors]}``.

        Returns:
            List of sets, each set being one SCC.
        """
        index_counter = [0]
        stack: List[str] = []
        on_stack: Set[str] = set()
        index_map: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        result: List[Set[str]] = []

        def strongconnect(v: str) -> None:
            index_map[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v)

            for w in adj.get(v, []):
                if w not in index_map:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_map[w])

            if lowlink[v] == index_map[v]:
                component: Set[str] = set()
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    component.add(w)
                    if w == v:
                        break
                result.append(component)

        for node in adj:
            if node not in index_map:
                strongconnect(node)

        return result

    # ── Floating / undriven net check ─────────────────────────────────────────

    def _check_floating_nets(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Detect nets with zero drivers (undriven / floating)."""
        diags: List[BugDiagnostic] = []
        for net in graph.nets.values():
            if len(net.drivers) == 0:
                sink_gates = [s.gate_id for s in net.sinks]
                diag = BugDiagnostic(
                    phase="PHASE_2_CIRCUIT",
                    rule_id=CIRC_ERC_004.rule_id,
                    severity=CIRC_ERC_004.severity,
                    message=(
                        f"Floating net '{net.net_id}': no drivers detected. "
                        f"Sinks: {', '.join(sink_gates[:5])}"
                    ),
                    circuit_probe=CircuitProbe(
                        net_names=[net.net_id],
                        gate_instances=sink_gates,
                    ),
                    highlight_style=HighlightStyle(
                        color_hex=CIRC_ERC_004.highlight_hex,
                        underline="dotted-violet",
                    ),
                )
                diags.append(diag)
        return diags

    # ── Multi-driver contention check ─────────────────────────────────────────

    def _check_multi_driver(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Detect nets with multiple drivers that lack tri-state control."""
        diags: List[BugDiagnostic] = []
        for net in graph.nets.values():
            if len(net.drivers) > 1 and not net.is_tristate:
                driver_gates = [d.gate_id for d in net.drivers]
                diag = BugDiagnostic(
                    phase="PHASE_2_CIRCUIT",
                    rule_id=CIRC_ERC_004.rule_id,
                    severity=CIRC_ERC_004.severity,
                    message=(
                        f"Multi-driver contention on net '{net.net_id}': "
                        f"{len(net.drivers)} drivers without tri-state. "
                        f"Drivers: {', '.join(driver_gates)}"
                    ),
                    circuit_probe=CircuitProbe(
                        net_names=[net.net_id],
                        gate_instances=driver_gates,
                    ),
                    highlight_style=HighlightStyle(
                        color_hex=CIRC_ERC_004.highlight_hex,
                        underline="dotted-violet",
                    ),
                )
                diags.append(diag)
        return diags

    # ── Excessive fan-out check ───────────────────────────────────────────────

    def _check_fan_out(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Flag gates whose fan-out exceeds ``self.max_fan_out``."""
        diags: List[BugDiagnostic] = []
        for gate_id, gate in graph.gates.items():
            actual_fan_out = graph.fan_out_of(gate_id)
            if actual_fan_out > self.max_fan_out:
                driven_nets = [n.net_id for n in graph.nets_driven_by(gate_id)]
                diag = BugDiagnostic(
                    phase="PHASE_2_CIRCUIT",
                    rule_id=CIRC_ERC_004.rule_id,
                    severity="WARNING",
                    message=(
                        f"Excessive fan-out on '{gate_id}': {actual_fan_out} sinks "
                        f"(threshold {self.max_fan_out}). "
                        f"Consider inserting a buffer tree."
                    ),
                    code_span=CodeSpan(
                        file=gate.rtl_file,
                        start_line=gate.rtl_line,
                        start_col=0,
                        end_line=gate.rtl_line,
                        end_col=0,
                    ) if gate.rtl_file else None,
                    circuit_probe=CircuitProbe(
                        gate_instances=[gate_id],
                        net_names=driven_nets,
                    ),
                    highlight_style=HighlightStyle(
                        color_hex="#F79009",
                        underline="dashed-amber",
                    ),
                )
                diags.append(diag)
        return diags


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CDC Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class CDCAnalyzer:
    """Clock Domain Crossing analysis.

    Traces clock trees from root sources to all sequential elements, then
    inspects every arc ``FF_A(CLK_A) → FF_B(CLK_B)`` where ``CLK_A != CLK_B``
    and verifies the presence of a proper 2-FF synchronizer chain.

    A 2-FF synchronizer is defined as two consecutive DFFs in *CLK_B*'s domain
    with a direct connection between them (no intervening combinational logic).

    Usage::

        analyzer = CDCAnalyzer(required_sync_stages=2)
        diagnostics = analyzer.analyze(graph)
    """

    def __init__(self, required_sync_stages: int = 2) -> None:
        self.required_sync_stages = required_sync_stages

    def analyze(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Run CDC analysis and return diagnostics for unsynchronized crossings.

        Args:
            graph: Parsed :class:`CircuitGraph` from Stage 2.1.

        Returns:
            List of :class:`BugDiagnostic` records for CIRC-CDC-002 violations.
        """
        diags: List[BugDiagnostic] = []

        # Build clock-domain map: domain_name → set of sequential gate IDs
        domain_map: Dict[str, Set[str]] = defaultdict(set)
        for gid, gate in graph.gates.items():
            if gate.is_sequential and gate.clock_domain:
                domain_map[gate.clock_domain].add(gid)

        # For every sequential → sequential edge crossing domains, check sync
        for src_id, successors in graph.adjacency.items():
            src_gate = graph.gates.get(src_id)
            if src_gate is None or not src_gate.is_sequential:
                continue

            for dst_id in successors:
                dst_gate = graph.gates.get(dst_id)
                if dst_gate is None or not dst_gate.is_sequential:
                    # The successor may be combinational; trace forward to find
                    # the first sequential element in another domain
                    seq_endpoints = self._trace_to_sequential(
                        graph, dst_id, visited=set()
                    )
                    for ep_id in seq_endpoints:
                        ep_gate = graph.gates.get(ep_id)
                        if ep_gate and ep_gate.clock_domain != src_gate.clock_domain:
                            sync_count = self._count_sync_stages(
                                graph, src_id, ep_id, ep_gate.clock_domain
                            )
                            if sync_count < self.required_sync_stages:
                                diags.append(
                                    self._build_cdc_diagnostic(
                                        graph, src_gate, ep_gate, sync_count
                                    )
                                )
                    continue

                if dst_gate.clock_domain == src_gate.clock_domain:
                    continue  # same domain, no CDC concern

                sync_count = self._count_sync_stages(
                    graph, src_id, dst_id, dst_gate.clock_domain
                )
                if sync_count < self.required_sync_stages:
                    diags.append(
                        self._build_cdc_diagnostic(
                            graph, src_gate, dst_gate, sync_count
                        )
                    )

        return diags

    # ── helpers ───────────────────────────────────────────────────────────────

    def _trace_to_sequential(
        self,
        graph: CircuitGraph,
        start_id: str,
        visited: Set[str],
    ) -> List[str]:
        """BFS forward from *start_id* until sequential elements are reached."""
        results: List[str] = []
        queue = [start_id]
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            gate = graph.gates.get(cur)
            if gate is None:
                continue
            if gate.is_sequential:
                results.append(cur)
                continue
            for succ in graph.adjacency.get(cur, set()):
                if succ not in visited:
                    queue.append(succ)
        return results

    def _count_sync_stages(
        self,
        graph: CircuitGraph,
        src_id: str,
        dst_id: str,
        dst_domain: str,
    ) -> int:
        """Count consecutive synchronizer DFFs in *dst_domain* between src and dst.

        A synchronizer stage is a DFF in the destination domain that lies on
        the direct path from the crossing point to ``dst_id``.
        """
        count = 0
        current = dst_id
        visited: Set[str] = set()
        while current and current not in visited:
            visited.add(current)
            gate = graph.gates.get(current)
            if gate is None:
                break
            if gate.is_sequential and gate.clock_domain == dst_domain:
                count += 1
            # Walk backward toward src
            preds = graph.reverse_adjacency.get(current, set())
            # Pick the predecessor on the path from src
            next_node = None
            for pred in preds:
                pred_gate = graph.gates.get(pred)
                if pred_gate and pred_gate.clock_domain != dst_domain:
                    break  # crossed back out of domain
                next_node = pred
            if next_node == src_id:
                break
            current = next_node
        return count

    def _build_cdc_diagnostic(
        self,
        graph: CircuitGraph,
        src_gate: GateVertex,
        dst_gate: GateVertex,
        sync_stages: int,
    ) -> BugDiagnostic:
        """Construct a CIRC-CDC-002 diagnostic."""
        return BugDiagnostic(
            phase="PHASE_2_CIRCUIT",
            rule_id=CIRC_CDC_002.rule_id,
            severity=CIRC_CDC_002.severity,
            message=(
                f"Unsynchronized clock-domain crossing: "
                f"{src_gate.instance_id} ({src_gate.clock_domain}) → "
                f"{dst_gate.instance_id} ({dst_gate.clock_domain}). "
                f"Sync stages found: {sync_stages}, "
                f"required: {self.required_sync_stages}."
            ),
            code_span=CodeSpan(
                file=src_gate.rtl_file,
                start_line=src_gate.rtl_line,
                start_col=0,
                end_line=src_gate.rtl_line,
                end_col=0,
            ) if src_gate.rtl_file else None,
            circuit_probe=CircuitProbe(
                gate_instances=[src_gate.instance_id, dst_gate.instance_id],
                clock_domains=[src_gate.clock_domain, dst_gate.clock_domain],
            ),
            highlight_style=HighlightStyle(
                color_hex=CIRC_CDC_002.highlight_hex,
                underline="dashed-amber",
            ),
            causal_trace=[
                CausalStep(
                    step_index=0,
                    label=f"Launch FF: {src_gate.instance_id} (domain {src_gate.clock_domain})",
                    file=src_gate.rtl_file,
                    line=src_gate.rtl_line,
                    net_or_var=src_gate.instance_id,
                ),
                CausalStep(
                    step_index=1,
                    label=f"Capture FF: {dst_gate.instance_id} (domain {dst_gate.clock_domain})",
                    file=dst_gate.rtl_file,
                    line=dst_gate.rtl_line,
                    net_or_var=dst_gate.instance_id,
                ),
            ],
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. STA Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class STAAnalyzer:
    """Static Timing Analysis via forward arrival / backward required propagation.

    For every register-to-register timing path in the graph, computes setup
    and hold slack using :func:`~bug_detection.core.scoring.setup_slack` and
    :func:`~bug_detection.core.scoring.hold_slack`.  Paths with negative slack
    are reported as CIRC-STA-001 violations.

    Usage::

        analyzer = STAAnalyzer(clock_period_ns=2.0, clock_uncertainty_ns=0.05)
        diagnostics = analyzer.analyze(graph)
    """

    def __init__(
        self,
        clock_period_ns: float = 1.0,
        clock_uncertainty_ns: float = 0.0,
    ) -> None:
        self.clock_period_ns = clock_period_ns
        self.clock_uncertainty_ns = clock_uncertainty_ns

    def analyze(self, graph: CircuitGraph) -> List[BugDiagnostic]:
        """Run STA on all timing paths and flag negative-slack violations.

        Args:
            graph: Parsed :class:`CircuitGraph` from Stage 2.1.

        Returns:
            List of :class:`BugDiagnostic` records for CIRC-STA-001 violations.
        """
        diags: List[BugDiagnostic] = []

        # If the graph has pre-extracted timing paths, analyse those.
        if graph.timing_paths:
            for path in graph.timing_paths:
                diags.extend(self._analyze_path(graph, path))
        else:
            # Discover register-to-register paths via DFS
            for path in self._discover_timing_paths(graph):
                diags.extend(self._analyze_path(graph, path))

        return diags

    # ── per-path analysis ─────────────────────────────────────────────────────

    def _analyze_path(
        self,
        graph: CircuitGraph,
        path: "TimingPath",
    ) -> List[BugDiagnostic]:
        """Compute setup and hold slack for a single timing path."""
        from .netlist_parser import TimingPath  # local to avoid circular at module level

        diags: List[BugDiagnostic] = []

        launch = graph.gates.get(path.launch_gate)
        capture = graph.gates.get(path.capture_gate)
        if not launch or not capture:
            return diags

        # Accumulate combinational delay along the path
        comb_delay = sum(
            graph.gates[gid].delay_ns
            for gid in path.through_gates
            if gid in graph.gates
        )
        if path.total_delay_ns > 0 and comb_delay == 0:
            # Fall back to the pre-computed total minus clk_to_q
            comb_delay = max(path.total_delay_ns - launch.clk_to_q_ns, 0.0)

        # Build TimingParams for setup slack
        setup_params = TimingParams(
            clk_period_ns=self.clock_period_ns,
            cap_clk_delay_ns=0.0,   # ideal capture clock
            lnch_clk_delay_ns=0.0,  # ideal launch clock
            clk_to_q_ns=launch.clk_to_q_ns,
            comb_delay_ns=comb_delay,
            setup_ns=capture.setup_ns,
            hold_ns=0.0,
            uncertainty_ns=self.clock_uncertainty_ns,
        )
        s_slack = setup_slack(setup_params)
        s_severity = classify_timing_slack(s_slack)

        if s_severity != "INFO":
            diags.append(self._build_sta_diagnostic(
                graph, path, launch, capture, "setup", s_slack, s_severity,
            ))

        # Build TimingParams for hold slack (use min comb delay — same here)
        hold_params = TimingParams(
            clk_period_ns=self.clock_period_ns,
            cap_clk_delay_ns=0.0,
            lnch_clk_delay_ns=0.0,
            clk_to_q_ns=launch.clk_to_q_ns,
            comb_delay_ns=comb_delay,
            setup_ns=0.0,
            hold_ns=capture.hold_ns,
            uncertainty_ns=self.clock_uncertainty_ns,
        )
        h_slack = hold_slack(hold_params)
        h_severity = classify_timing_slack(h_slack)

        if h_severity != "INFO":
            diags.append(self._build_sta_diagnostic(
                graph, path, launch, capture, "hold", h_slack, h_severity,
            ))

        return diags

    def _build_sta_diagnostic(
        self,
        graph: CircuitGraph,
        path: "TimingPath",
        launch: GateVertex,
        capture: GateVertex,
        check_type: str,
        slack_ns: float,
        severity: str,
    ) -> BugDiagnostic:
        """Construct a CIRC-STA-001 diagnostic for a failing timing path."""
        all_gates = [path.launch_gate] + path.through_gates + [path.capture_gate]
        return BugDiagnostic(
            phase="PHASE_2_CIRCUIT",
            rule_id=CIRC_STA_001.rule_id,
            severity=severity,
            message=(
                f"Negative {check_type} slack ({slack_ns:+.3f} ns) on path "
                f"{launch.instance_id} → {capture.instance_id} "
                f"(path {path.path_id})."
            ),
            slack_ns=slack_ns,
            code_span=CodeSpan(
                file=launch.rtl_file,
                start_line=launch.rtl_line,
                start_col=0,
                end_line=launch.rtl_line,
                end_col=0,
            ) if launch.rtl_file else None,
            circuit_probe=CircuitProbe(
                gate_instances=all_gates,
                clock_domains=list({launch.clock_domain, capture.clock_domain}),
                slack_ns=slack_ns,
            ),
            highlight_style=HighlightStyle(
                color_hex=CIRC_STA_001.highlight_hex if severity == "CRITICAL" else "#F79009",
                underline="wavy-crimson" if severity == "CRITICAL" else "dashed-amber",
                cone=all_gates,
            ),
            causal_trace=[
                CausalStep(
                    step_index=i,
                    label=f"{'Launch' if i == 0 else 'Capture' if gid == path.capture_gate else 'Through'}: {gid}",
                    file=graph.gates[gid].rtl_file if gid in graph.gates else "",
                    line=graph.gates[gid].rtl_line if gid in graph.gates else 0,
                    net_or_var=gid,
                )
                for i, gid in enumerate(all_gates)
            ],
        )

    # ── path discovery ────────────────────────────────────────────────────────

    def _discover_timing_paths(self, graph: CircuitGraph) -> List["TimingPath"]:
        """Auto-discover register-to-register paths when none are provided.

        Performs DFS from every sequential output, traversing combinational
        gates, until another sequential input is reached.
        """
        from .netlist_parser import TimingPath

        paths: List[TimingPath] = []
        seq_ids = {g.instance_id for g in graph.sequential_gates()}
        path_counter = 0

        for launch_id in seq_ids:
            # DFS through combinational gates
            stack: List[Tuple[str, List[str], float]] = [
                (launch_id, [], 0.0)
            ]
            visited: Set[str] = set()

            while stack:
                current, through, delay = stack.pop()
                if current in visited and current != launch_id:
                    continue
                visited.add(current)

                for succ in graph.adjacency.get(current, set()):
                    succ_gate = graph.gates.get(succ)
                    if succ_gate is None:
                        continue

                    if succ_gate.is_sequential:
                        # Found capture register
                        paths.append(TimingPath(
                            path_id=f"auto_P{path_counter}",
                            launch_gate=launch_id,
                            capture_gate=succ,
                            through_gates=list(through),
                            total_delay_ns=delay,
                        ))
                        path_counter += 1
                    else:
                        if succ not in visited:
                            stack.append((
                                succ,
                                through + [succ],
                                delay + succ_gate.delay_ns,
                            ))

        return paths

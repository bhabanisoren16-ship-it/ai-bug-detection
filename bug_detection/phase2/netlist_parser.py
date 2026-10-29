"""
Stage 2.1 — HDL Elaboration, Netlist Synthesis & Hypergraph Extraction.

Parses a netlist JSON representation into a directed hypergraph G = (V, E)
suitable for downstream ERC, CDC, STA, and GNN-based fault localization.

Supported gate types:
    LUT, AND, OR, XOR, DFF (D-flip-flop), LATCH, SRAM, MUX, CARRY, BUF (buffer)

Each vertex carries:
    gate_type, clock_domain, delay_ns, clk_to_q_ns, setup_ns, hold_ns,
    fan_in, fan_out, toggle_rate, scoap_observability, scoap_controllability

Nets connect driver pins to sink pins with bidirectional cross-references.
RTL source file/line, schematic coordinates (x, y), and layout bounding box
are preserved on every vertex for cross-probe highlighting (Stage 2.5).

Reference: Section 3.2 of the AI & Software Bug Detection Blueprint.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Gate type constants ──────────────────────────────────────────────────────

SEQUENTIAL_GATE_TYPES: Set[str] = {"DFF", "LATCH", "SRAM"}
COMBINATIONAL_GATE_TYPES: Set[str] = {"LUT", "AND", "OR", "XOR", "MUX", "CARRY", "BUF"}
ALL_GATE_TYPES: Set[str] = SEQUENTIAL_GATE_TYPES | COMBINATIONAL_GATE_TYPES


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class GateVertex:
    """A single gate / cell instance in the elaborated netlist.

    Attributes:
        instance_id:  Unique instance name (e.g. ``u_alu/add_0/U42``).
        gate_type:    One of :data:`ALL_GATE_TYPES`.
        clock_domain: Clock domain label (``""`` for combinational gates).
        delay_ns:     Combinational propagation delay in nanoseconds.
        clk_to_q_ns:  Clock-to-Q delay (sequential elements only).
        setup_ns:     Setup time requirement (sequential elements only).
        hold_ns:      Hold time requirement (sequential elements only).
        fan_in:       Number of input pins connected.
        fan_out:      Number of output pins connected.
        toggle_rate:  Estimated switching activity in [0, 1].
        scoap_observability:   SCOAP observability metric.
        scoap_controllability: SCOAP controllability metric.
        rtl_file:     RTL source file path.
        rtl_line:     RTL source line number.
        schematic_x:  Schematic canvas x-coordinate.
        schematic_y:  Schematic canvas y-coordinate.
        layout_bbox:  Physical layout bounding box ``[x0, y0, x1, y1]``.
        properties:   Arbitrary extra metadata.
    """

    instance_id: str
    gate_type: str = "LUT"
    clock_domain: str = ""
    delay_ns: float = 0.0
    clk_to_q_ns: float = 0.0
    setup_ns: float = 0.0
    hold_ns: float = 0.0
    fan_in: int = 0
    fan_out: int = 0
    toggle_rate: float = 0.0
    scoap_observability: float = 0.0
    scoap_controllability: float = 0.0
    rtl_file: str = ""
    rtl_line: int = 0
    schematic_x: float = 0.0
    schematic_y: float = 0.0
    layout_bbox: List[float] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)

    # ── runtime cross-refs (populated during parse) ──
    input_nets: List[str] = field(default_factory=list)
    output_nets: List[str] = field(default_factory=list)

    @property
    def is_sequential(self) -> bool:
        """Return ``True`` for DFF, LATCH, or SRAM."""
        return self.gate_type in SEQUENTIAL_GATE_TYPES


@dataclass
class NetPin:
    """A pin reference on a net — either a driver or a sink.

    Attributes:
        gate_id:  Instance ID of the gate owning this pin.
        pin_name: Pin name on the gate (e.g. ``D``, ``Q``, ``A0``).
    """

    gate_id: str
    pin_name: str = ""


@dataclass
class NetEdge:
    """A single net (hyperedge) connecting one or more drivers to sinks.

    In a well-formed netlist every net has exactly one driver except for
    tri-state buses.  The parser records all drivers to enable ERC checks
    for multi-driver contention.

    Attributes:
        net_id:       Unique net identifier.
        drivers:      List of driving :class:`NetPin` references.
        sinks:        List of sink :class:`NetPin` references.
        is_tristate:  Whether the net has an explicit tri-state controller.
        capacitance_pf: Total net capacitance (for fan-out / delay checks).
        properties:   Arbitrary extra metadata.
    """

    net_id: str
    drivers: List[NetPin] = field(default_factory=list)
    sinks: List[NetPin] = field(default_factory=list)
    is_tristate: bool = False
    capacitance_pf: float = 0.0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimingPath:
    """A registered start → combinational → registered end timing path.

    Attributes:
        path_id:       Unique path identifier.
        launch_gate:   Instance ID of the launch sequential element.
        capture_gate:  Instance ID of the capture sequential element.
        through_gates: Ordered list of combinational gate IDs on the path.
        total_delay_ns: Accumulated path delay.
    """

    path_id: str = ""
    launch_gate: str = ""
    capture_gate: str = ""
    through_gates: List[str] = field(default_factory=list)
    total_delay_ns: float = 0.0


@dataclass
class CircuitGraph:
    """Directed hypergraph representation of the elaborated netlist.

    This is the primary data structure consumed by downstream analyzers
    (ERC, CDC, STA, Formal, GNN fault localization, Cross-probe).

    Attributes:
        design_name:     Top-level design/module name.
        gates:           ``{instance_id: GateVertex}`` dictionary.
        nets:            ``{net_id: NetEdge}`` dictionary.
        adjacency:       ``{gate_id: set(successor_gate_ids)}``.
        reverse_adjacency: ``{gate_id: set(predecessor_gate_ids)}``.
        timing_paths:    Extracted register-to-register timing paths.
        clock_sources:   Root clock net IDs.
        metadata:        Design-level metadata preserved from the input.
    """

    design_name: str = ""
    gates: Dict[str, GateVertex] = field(default_factory=dict)
    nets: Dict[str, NetEdge] = field(default_factory=dict)
    adjacency: Dict[str, Set[str]] = field(default_factory=dict)
    reverse_adjacency: Dict[str, Set[str]] = field(default_factory=dict)
    timing_paths: List[TimingPath] = field(default_factory=list)
    clock_sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── query helpers ──

    def successors(self, gate_id: str) -> Set[str]:
        """Return the set of direct successor gate IDs."""
        return self.adjacency.get(gate_id, set())

    def predecessors(self, gate_id: str) -> Set[str]:
        """Return the set of direct predecessor gate IDs."""
        return self.reverse_adjacency.get(gate_id, set())

    def sequential_gates(self) -> List[GateVertex]:
        """Return all sequential elements (DFF, LATCH, SRAM)."""
        return [g for g in self.gates.values() if g.is_sequential]

    def combinational_gates(self) -> List[GateVertex]:
        """Return all combinational elements."""
        return [g for g in self.gates.values() if not g.is_sequential]

    def nets_driven_by(self, gate_id: str) -> List[NetEdge]:
        """Return nets driven by *gate_id*."""
        return [
            net for net in self.nets.values()
            if any(d.gate_id == gate_id for d in net.drivers)
        ]

    def nets_sinking_to(self, gate_id: str) -> List[NetEdge]:
        """Return nets that sink into *gate_id*."""
        return [
            net for net in self.nets.values()
            if any(s.gate_id == gate_id for s in net.sinks)
        ]

    def fan_out_of(self, gate_id: str) -> int:
        """Compute total sink count across all driven nets."""
        return sum(
            len(net.sinks) for net in self.nets_driven_by(gate_id)
        )


# ─── Parser ───────────────────────────────────────────────────────────────────

class NetlistParser:
    """Parse a netlist JSON dictionary into a :class:`CircuitGraph`.

    Expected JSON schema::

        {
          "design_name": "my_soc",
          "clock_sources": ["clk_100", "clk_50"],
          "gates": {
            "U0": {
              "gate_type": "DFF",
              "clock_domain": "clk_100",
              "delay_ns": 0.05,
              "clk_to_q_ns": 0.12,
              "setup_ns": 0.04,
              "hold_ns": 0.02,
              "toggle_rate": 0.35,
              "scoap_observability": 4,
              "scoap_controllability": 3,
              "rtl_file": "alu.v",
              "rtl_line": 42,
              "schematic_xy": [120.0, 340.0],
              "layout_bbox": [1000, 2000, 1100, 2100],
              "input_pins": ["D", "CLK"],
              "output_pins": ["Q"]
            },
            ...
          },
          "nets": {
            "n0": {
              "drivers": [{"gate_id": "U0", "pin_name": "Q"}],
              "sinks":   [{"gate_id": "U1", "pin_name": "A0"},
                          {"gate_id": "U2", "pin_name": "B"}],
              "is_tristate": false,
              "capacitance_pf": 0.35
            },
            ...
          },
          "timing_paths": [
            {
              "path_id": "P0",
              "launch_gate": "U0",
              "capture_gate": "U3",
              "through_gates": ["U1", "U2"],
              "total_delay_ns": 1.45
            },
            ...
          ]
        }

    Usage::

        parser = NetlistParser()
        graph = parser.parse(netlist_dict)
    """

    # ── public API ──

    @classmethod
    def parse(cls, netlist_dict: dict) -> CircuitGraph:
        """Parse the netlist JSON dict and return a populated :class:`CircuitGraph`.

        Supports both dictionary and list layouts for gates and nets, as well as
        string pin identifiers.
        """
        inst = cls()
        design_name = netlist_dict.get("design_name") or netlist_dict.get("module") or "untitled"
        graph = CircuitGraph(
            design_name=design_name,
            clock_sources=list(netlist_dict.get("clock_sources", [])),
            metadata=netlist_dict.get("metadata", {}),
        )

        inst._parse_gates(netlist_dict.get("gates", {}), graph)
        inst._parse_nets(netlist_dict.get("nets", {}), graph)
        inst._build_adjacency(graph)
        inst._compute_fan_metrics(graph)
        inst._parse_timing_paths(netlist_dict.get("timing_paths", []), graph)

        return graph

    # ── internal helpers ──

    def _parse_gates(self, gates_data: Any, graph: CircuitGraph) -> None:
        """Populate ``graph.gates`` from dictionary or list of gate specs."""
        gates_dict: Dict[str, dict] = {}
        if isinstance(gates_data, list):
            for g in gates_data:
                g_id = g.get("id") or g.get("name") or g.get("instance_id", "")
                if g_id:
                    gates_dict[g_id] = g
        elif isinstance(gates_data, dict):
            gates_dict = gates_data

        for inst_id, gd in gates_dict.items():
            raw_type = gd.get("gate_type") or gd.get("type") or "LUT"
            gate_type = str(raw_type).upper()
            if gate_type not in ALL_GATE_TYPES:
                # Fallback to LUT for generic cell types
                gate_type = "LUT"

            schematic_xy = gd.get("schematic_xy", [0.0, 0.0])
            vertex = GateVertex(
                instance_id=inst_id,
                gate_type=gate_type,
                clock_domain=gd.get("clock_domain", ""),
                delay_ns=float(gd.get("delay_ns", 0.0)),
                clk_to_q_ns=float(gd.get("clk_to_q_ns", 0.0)),
                setup_ns=float(gd.get("setup_ns", 0.0)),
                hold_ns=float(gd.get("hold_ns", 0.0)),
                toggle_rate=float(gd.get("toggle_rate", 0.0)),
                scoap_observability=float(gd.get("scoap_observability", 0.0)),
                scoap_controllability=float(gd.get("scoap_controllability", 0.0)),
                rtl_file=gd.get("rtl_file", ""),
                rtl_line=int(gd.get("rtl_line", 0)),
                schematic_x=float(schematic_xy[0]) if len(schematic_xy) > 0 else 0.0,
                schematic_y=float(schematic_xy[1]) if len(schematic_xy) > 1 else 0.0,
                layout_bbox=[float(v) for v in gd.get("layout_bbox", [])],
                properties=gd.get("properties", {}),
            )
            graph.gates[inst_id] = vertex

    def _parse_nets(self, nets_data: Any, graph: CircuitGraph) -> None:
        """Populate ``graph.nets`` and set cross-references on gate vertices."""
        nets_dict: Dict[str, dict] = {}
        if isinstance(nets_data, list):
            for n in nets_data:
                n_id = n.get("name") or n.get("net_id") or n.get("id", "")
                if n_id:
                    nets_dict[n_id] = n
        elif isinstance(nets_data, dict):
            nets_dict = nets_data

        for net_id, nd in nets_dict.items():
            drivers: List[NetPin] = []
            for drv in nd.get("drivers", []):
                if isinstance(drv, str):
                    pin = NetPin(gate_id=drv, pin_name="")
                elif isinstance(drv, dict):
                    pin = NetPin(gate_id=drv.get("gate_id") or drv.get("id", ""),
                                 pin_name=drv.get("pin_name", ""))
                else:
                    continue
                drivers.append(pin)
                if pin.gate_id in graph.gates:
                    gate = graph.gates[pin.gate_id]
                    if net_id not in gate.output_nets:
                        gate.output_nets.append(net_id)

            sinks: List[NetPin] = []
            for snk in nd.get("sinks", []):
                if isinstance(snk, str):
                    pin = NetPin(gate_id=snk, pin_name="")
                elif isinstance(snk, dict):
                    pin = NetPin(gate_id=snk.get("gate_id") or snk.get("id", ""),
                                 pin_name=snk.get("pin_name", ""))
                else:
                    continue
                sinks.append(pin)
                if pin.gate_id in graph.gates:
                    gate = graph.gates[pin.gate_id]
                    if net_id not in gate.input_nets:
                        gate.input_nets.append(net_id)

            edge = NetEdge(
                net_id=net_id,
                drivers=drivers,
                sinks=sinks,
                is_tristate=bool(nd.get("is_tristate", False)),
                capacitance_pf=float(nd.get("capacitance_pf", 0.0)),
                properties=nd.get("properties", {}),
            )
            graph.nets[net_id] = edge

    def _build_adjacency(self, graph: CircuitGraph) -> None:
        """Build forward and reverse adjacency from net driver→sink arcs."""
        for gate_id in graph.gates:
            graph.adjacency.setdefault(gate_id, set())
            graph.reverse_adjacency.setdefault(gate_id, set())

        for net in graph.nets.values():
            driver_ids = {d.gate_id for d in net.drivers if d.gate_id in graph.gates}
            sink_ids = {s.gate_id for s in net.sinks if s.gate_id in graph.gates}
            for drv in driver_ids:
                for snk in sink_ids:
                    if drv != snk:
                        graph.adjacency[drv].add(snk)
                        graph.reverse_adjacency[snk].add(drv)

    def _compute_fan_metrics(self, graph: CircuitGraph) -> None:
        """Compute fan-in and fan-out counts on each gate vertex."""
        for gate_id, gate in graph.gates.items():
            gate.fan_in = len(graph.reverse_adjacency.get(gate_id, set()))
            gate.fan_out = len(graph.adjacency.get(gate_id, set()))

    def _parse_timing_paths(
        self, paths_list: List[dict], graph: CircuitGraph
    ) -> None:
        """Parse pre-extracted timing paths into :class:`TimingPath` objects."""
        for pd in paths_list:
            path = TimingPath(
                path_id=pd.get("path_id", ""),
                launch_gate=pd.get("launch_gate", ""),
                capture_gate=pd.get("capture_gate", ""),
                through_gates=list(pd.get("through_gates", [])),
                total_delay_ns=float(pd.get("total_delay_ns", 0.0)),
            )
            graph.timing_paths.append(path)

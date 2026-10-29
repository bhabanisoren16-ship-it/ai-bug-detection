# AI Bug Detection & Highlighting System

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/bhabanisoren16-ship-it/ai-bug-detection)

> **Dual-Phase Automated Defect Localization, Multi-Layer Visual Highlighting & Hardware-Software Co-Verification Engine**  
> Built strictly in accordance with `ai_software_bug_detection_phase_by_phase.pdf` and David J. Agans' *"Debugging: The 9 Indispensable Rules"*.

---

## 🚀 Architectural Overview

Modern cyber-physical systems, embedded firmware, and custom silicon accelerators require a unified verification pipeline capable of finding and highlighting defects across both **software source code** (Phase 1) and **electronic hardware descriptions** (Phase 2).

```
   Source Code (C, Python, Rust)                 Verilog / Netlist / SPICE
                 │                                           │
  ┌──────────────▼─────────────┐              ┌──────────────▼─────────────┐
  │   PHASE 1: CODE ENGINE     │              │  PHASE 2: CIRCUIT ENGINE   │
  │ • Lossless AST Indexing    │              │ • Netlist Hypergraph G(V,E)│
  │ • CFG/DFG Taint Analysis   │              │ • Static Timing (STA)      │
  │ • Ochiai SBFL Localization │              │ • Structural ERC & CDC     │
  │ • AI / Semantic Detectors  │              │ • Bounded Model Checking   │
  │ • 3-Layer Visual Overlays  │              │ • 4-View Synchronized Cross│
  └──────────────┬─────────────┘              └──────────────┬─────────────┘
                 │                                           │
                 └─────────────────────┬─────────────────────┘
                                       │
                      ┌────────────────▼────────────────┐
                      │    STANDARDIZED TELEMETRY       │
                      │  • SARIF v2.1.0 Protocol        │
                      │  • Unified Diagnostic Schema    │
                      │  • Interactive Web Dashboard    │
                      └─────────────────────────────────┘
```

---

## 📐 Mathematical & Algorithmic Foundations

The system uses 5 mathematical scoring and physical margin equations:

1. **Ochiai Spectrum-Based Fault Localization (SBFL)**:
   $$S_{ochiai}(e) = \frac{n_{ef}}{\sqrt{(n_{ef} + n_{nf}) \cdot (n_{ef} + n_{ep})}}$$
   - $n_{ef}$: Failing tests executing statement $e$
   - $n_{ep}$: Passing tests executing statement $e$
   - $n_{nf}$: Failing tests *not* executing statement $e$
   - Highlighted when $S_{ochiai} \ge 0.65$.

2. **Hybrid AI-Static Priority Score ($R_{total}$)**:
   $$R_{total}(e) = 0.35 \cdot S_{rule}(e) + 0.35 \cdot S_{ochiai}(e) + 0.30 \cdot P_{gnn}(bug \mid e)$$
   - Combines deterministic rules, SBFL spectrum suspiciousness, and GNN/LLM probability.
   - Critical alert flagged when $R_{total} \ge 0.75$.

3. **Static Timing Setup Slack**:
   $$\text{Slack}_{setup} = (T_{clk} + T_{cap\_clk}) - (T_{lnch\_clk} + T_{cq} + T_{comb\_max} + T_{su} + T_{unc})$$
   - Critical violation if $\text{Slack} < 0.0\text{ ns}$ (Rule `CIRC-STA-001`).
   - Tight guardband warning if $0.0 \le \text{Slack} < 0.15\text{ ns}$.

4. **Static Timing Hold Slack**:
   $$\text{Slack}_{hold} = (T_{lnch\_clk} + T_{cq} + T_{comb\_min}) - (T_{cap\_clk} + T_{hold} + T_{unc})$$
   - Critical violation if $\text{Slack}_{hold} < 0.0\text{ ns}$.

5. **Elmore RC Wire Delay & Analog IR-Drop**:
   $$\tau_D = \sum_i (R_i \cdot C_{downstream\_i}), \quad \Delta V = I_{branch} \cdot R_{metal}$$
   - Flagged when $\Delta V > 5\% \cdot V_{DD}$ (Rule `CIRC-PWR-005`).

---

## 📋 10-Rule Production Detection Catalog

| Rule ID | Phase | Category | Severity Tier | Color Hex | Automated Fix Strategy |
|---|---|---|---|---|---|
| `CODE-MEM-001` | Phase 1 | Use-After-Free / Double Free | `CRITICAL` | `#D92D20` | Nullify pointer or insert guard check. |
| `CODE-MEM-002` | Phase 1 | Out-of-Bounds Buffer Write | `CRITICAL` | `#D92D20` | Clamp boundary to `range(len - 1)`. |
| `CODE-NUM-003` | Phase 1 | Unchecked Division by Zero | `CRITICAL` | `#D92D20` | Synthesize preceding zero-divisor guard. |
| `CODE-SEC-004` | Phase 1 | Unsanitized Taint Sink | `CRITICAL` | `#D92D20` | Replace string concatenation with parameterized API. |
| `CODE-CON-005` | Phase 1 | Data Race / Missing Lock | `WARNING` | `#F79009` | Wrap critical section with mutex lock. |
| `CIRC-STA-001` | Phase 2 | Setup / Hold Timing Violation | `CRITICAL` | `#D92D20` | Insert pipeline register or buffer delay. |
| `CIRC-CDC-002` | Phase 2 | Unsynchronized Clock Crossing | `WARNING` | `#F79009` | Instantiate 2-FF synchronizer or async FIFO. |
| `CIRC-ERC-003` | Phase 2 | Combinational Feedback Loop | `CRITICAL` | `#D92D20` | Break combinational loop with clocked D-FF. |
| `CIRC-ERC-004` | Phase 2 | Floating Net / Multi-Driver | `VIOLET_NET` | `#7A5AF8` | Tie undriven net to rail or multiplex drivers. |
| `CIRC-PWR-005` | Phase 2 | SPICE IR-Drop / Latch-Up | `CRITICAL` | `#D92D20` | Widen M3/M4 straps & add decap cells. |

---

## 🎨 Visual Highlighting Mechanics & Cyber Theme Palette

The system features a custom high-contrast cyber theme palette:
- **Obsidian Void (`#030407`)**: Deep base canvas and low-distraction backdrop for code and netlist editors.
- **Electric Cobalt (`#1558C9`)**: Primary structural accent, brand identity, telemetry status, active navigation borders, and info diagnostics.
- **Cyber Neon Lime (`#D4FF24`)**: High-visibility attention markers, primary action CTA buttons, AI synthesis diff patches, score pill values, and live engine status pulse.

### Phase 1: 3-Layer Code Visual Overlays
- **Layer 1 — Exact Token Span Highlight**: Color tints and wavy underlines across offending columns.
- **Layer 2 — Causal Data-Flow Trail**: Numbered inline breadcrumb badges showing backward slice history:
  `[Step 1: Allocated (L15)] → [Step 2: Freed (L17)] → [Step 3: Crash: Dereferenced (L19)]`
- **Layer 3 — Ghost-Text Inline Diff Preview**: Red strikethrough for buggy code and neon lime (`#D4FF24`) insertion styling for verified repair patches.

### Phase 2: Synchronized 4-View Cross-Probe
- **View 1 — RTL Source Editor**: Verilog/VHDL statement location (`core_alu.sv:84`).
- **View 2 — Gate Schematic Canvas**: Negative slack logic cone colored with background gates dimmed to 25% opacity.
- **View 3 — Waveform Viewer**: Vertical cursors at $t_{launch}, t_{glitch}, t_{capture}$ with translucent crimson violation window.
- **View 4 — Physical GDSII / Floorplan**: High-contrast bounding box over metal layer coordinates (`["M3", 142.4, 88.0, 219.6, 104.2]`).

---

## 💻 Installation & Usage

### 1. Requirements
- Python 3.9+
- Flask & Flask-CORS

```bash
pip install -r requirements.txt
```

### 2. Launch the Web Dashboard
```bash
python web/app.py
```
Open your browser at `http://localhost:5000` to interact with the visual dashboard.

### 3. Programmatic Python API
```python
from bug_detection.engine import UnifiedBugHighlightEngine

engine = UnifiedBugHighlightEngine()

# Phase 1: Code Analysis
with open("tests/sample_buggy_code.py") as f:
    source_code = f.read()
diagnostics = engine.analyze_phase1_code("sample.py", source_code)
for diag in diagnostics:
    print(f"[{diag['severity']}] {diag['rule_id']}: {diag['message']}")

# Phase 2: Circuit Netlist Analysis
import json
with open("tests/sample_netlist.json") as f:
    netlist = json.load(f)
circ_diags = engine.analyze_phase2_circuit(netlist)
for diag in circ_diags:
    print(f"[{diag['severity']}] {diag['rule_id']}: {diag['message']}")
```

### 4. Run Test Suite
```bash
python -m unittest discover tests
```
Runs all 24 unit and integration tests across Phase 1 and Phase 2.

---

## 📂 Project Structure

```
d:\BUG DETECTION\
├── ai_software_bug_detection_phase_by_phase.pdf   # Blueprint reference specification
├── README.md
├── requirements.txt
├── setup.py
├── bug_detection/
│   ├── core/
│   │   ├── schemas.py           # Unified JSON & SARIF diagnostic telemetry
│   │   ├── rules_catalog.py     # 10-rule production catalog
│   │   └── scoring.py           # Ochiai SBFL, Hybrid R_total, STA timing formulas
│   ├── phase1/                  # Phase 1: Code Debugging Pipeline
│   │   ├── ast_analyzer.py      # Stage 1.1: AST parsing, error recovery, byte mapping
│   │   ├── cfg_dfg_analyzer.py  # Stage 1.2: CFG/DFG, taint, memory lifecycle
│   │   ├── dynamic_analyzer.py  # Stage 1.3: Dynamic instrumentation & Ochiai SBFL
│   │   ├── ai_detector.py       # Stage 1.4: AI/semantic bug detection & ranking
│   │   └── highlighter.py       # Stage 1.5: 3-layer visual highlighting & LSP output
│   ├── phase2/                  # Phase 2: Hardware Circuit Debugging Pipeline
│   │   ├── netlist_parser.py    # Stage 2.1: HDL elaboration into hypergraph G(V,E)
│   │   ├── erc_cdc_sta.py       # Stage 2.2: Structural ERC, CDC, and Static Timing
│   │   ├── formal_checker.py    # Stage 2.3: Bounded Model Checking (BMC) & X-propagation
│   │   ├── gnn_fault_locator.py # Stage 2.4: GNN fault probability & analog IR-drop
│   │   └── cross_probe.py       # Stage 2.5: Synchronized 4-view cross-probe engine
│   └── engine.py                # UnifiedBugHighlightEngine orchestrator
├── web/                         # Interactive Web Dashboard
│   ├── app.py                   # Flask server with REST API
│   ├── templates/index.html     # High-tech single page UI
│   └── static/
│       ├── css/style.css        # Dark theme & high-contrast severity styles
│       └── js/app.js            # Client-side analysis & visual annotations
├── tests/
│   ├── test_phase1.py           # Phase 1 test suite (15 tests)
│   ├── test_phase2.py           # Phase 2 test suite (9 tests)
│   ├── sample_buggy_code.py     # Sample test code with known defects
│   └── sample_netlist.json      # Sample test netlist with timing/CDC/ERC faults
└── sarif/                       # SARIF v2.1.0 exports directory
```


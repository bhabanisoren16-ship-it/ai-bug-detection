"""
Phase 1: Software Code Debugging — 5-Stage Detection & Highlighting.

Stage 1.1: ASTAnalyzer — Lexical, syntactic & lossless AST indexing
Stage 1.2: CFGDFGAnalyzer — Static CFG, DFG & taint propagation
Stage 1.3: SpectrumAnalyzer — Dynamic instrumentation & Ochiai SBFL
Stage 1.4: AIDetector — Semantic bug detection & root-cause ranking
Stage 1.5: Phase1Highlighter — Multi-layer visual highlighting mechanics
"""

from bug_detection.phase1.ast_analyzer import ASTAnalyzer, ASTNodeIndexer, SourceMap
from bug_detection.phase1.cfg_dfg_analyzer import CFGDFGAnalyzer
from bug_detection.phase1.dynamic_analyzer import SpectrumAnalyzer, TestExecutionRecord
from bug_detection.phase1.ai_detector import AIDetector
from bug_detection.phase1.highlighter import Phase1Highlighter

__all__ = [
    "ASTAnalyzer",
    "ASTNodeIndexer",
    "SourceMap",
    "CFGDFGAnalyzer",
    "SpectrumAnalyzer",
    "TestExecutionRecord",
    "AIDetector",
    "Phase1Highlighter",
]

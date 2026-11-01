"""
Unit and Integration Tests for Security Checks and Defensive Capabilities.

Covers:
1. Security rules catalog registration (CODE-SEC-004, CODE-SEC-006..009, CIRC-SEC-006).
2. Phase 1 detection of Command Injection, Path Traversal, Insecure Deserialization, Hardcoded Secrets.
3. Phase 2 detection of Hardware Trojan / Unauthenticated Test Ports.
4. Pragmatic Security Defense Posture auditing (Defensive Score, Grade, Directives).
5. Web Server defensive HTTP response headers (CSP, nosniff, SAMEORIGIN, etc.).
6. Maximum content-length DoS payload shield.
"""

import os
import sys
import json
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from bug_detection.core.rules_catalog import ALL_RULES, get_rule
from bug_detection.core.agans_rules import get_agans_mapping_for_rule
from bug_detection.core.pragmatic_programmer import PragmaticAnalyzer
from web.app import app, _analyze_phase1_code, _analyze_phase2_circuit


class TestSecurityAndDefenseCapabilities(unittest.TestCase):
    """Test suite for security checks and defensive hardening."""

    def setUp(self):
        self.client = app.test_client()

    def test_security_rules_catalog_registration(self):
        """Verify all security rules are formally registered with CRITICAL severity and Agans mappings."""
        security_rules = [
            "CODE-SEC-004",  # Unsanitized Taint Sink
            "CODE-SEC-006",  # Command Injection
            "CODE-SEC-007",  # Path Traversal
            "CODE-SEC-008",  # Insecure Deserialization
            "CODE-SEC-009",  # Hardcoded Secret
            "CIRC-SEC-006",  # Hardware Trojan / Test Port
        ]
        for s_rule in security_rules:
            self.assertIn(s_rule, ALL_RULES, f"Rule {s_rule} missing from catalog")
            rule = get_rule(s_rule)
            self.assertEqual(rule.severity, "CRITICAL")
            self.assertIn("security", rule.tags)
            # Verify Agans Rule mapping
            mapping = get_agans_mapping_for_rule(s_rule)
            self.assertIn("primary_rule", mapping)
            self.assertIn("primary_info", mapping)

    def test_command_injection_detection(self):
        """CODE-SEC-006: Subprocess with shell=True or dynamic string should be detected."""
        code = (
            "import subprocess\n"
            "user_cmd = input('cmd: ')\n"
            "subprocess.run('ls -la ' + user_cmd, shell=True)\n"
        )
        diags = _analyze_phase1_code(code, "python")
        sec_diags = [d for d in diags if d.rule_id == "CODE-SEC-006"]
        self.assertGreaterEqual(len(sec_diags), 1)
        self.assertEqual(sec_diags[0].severity, "CRITICAL")
        self.assertIn("Command Injection", sec_diags[0].message)
        self.assertIn("shell=False", sec_diags[0].auto_remediation.unified_diff)

    def test_path_traversal_detection(self):
        """CODE-SEC-007: Unguarded file open on user-controlled path should be detected."""
        code = (
            "def read_profile(user_path):\n"
            "    with open('uploads/' + user_path, 'r') as f:\n"
            "        return f.read()\n"
        )
        diags = _analyze_phase1_code(code, "python")
        sec_diags = [d for d in diags if d.rule_id == "CODE-SEC-007"]
        self.assertGreaterEqual(len(sec_diags), 1)
        self.assertEqual(sec_diags[0].severity, "CRITICAL")
        self.assertIn("Path Traversal", sec_diags[0].message)
        self.assertIn("realpath", sec_diags[0].auto_remediation.unified_diff)

    def test_insecure_deserialization_detection(self):
        """CODE-SEC-008: Untrusted pickle.loads should be detected and patched to safe deserializer."""
        code = (
            "import pickle\n"
            "def unpack(payload):\n"
            "    data = pickle.loads(payload)\n"
            "    return data\n"
        )
        diags = _analyze_phase1_code(code, "python")
        sec_diags = [d for d in diags if d.rule_id == "CODE-SEC-008"]
        self.assertGreaterEqual(len(sec_diags), 1)
        self.assertEqual(sec_diags[0].severity, "CRITICAL")
        self.assertIn("Insecure Deserialization", sec_diags[0].message)
        self.assertIn("json.loads", sec_diags[0].auto_remediation.unified_diff)

    def test_hardcoded_secret_detection(self):
        """CODE-SEC-009: High-entropy secret credential in source code should be flagged."""
        code = (
            "import requests\n"
            "API_KEY = 'mock_secret_vault_token_48729384729384729'\n"
            "r = requests.get('https://api.example.com', headers={'Auth': API_KEY})\n"
        )
        diags = _analyze_phase1_code(code, "python")
        sec_diags = [d for d in diags if d.rule_id == "CODE-SEC-009"]
        self.assertGreaterEqual(len(sec_diags), 1)
        self.assertEqual(sec_diags[0].severity, "CRITICAL")
        self.assertIn("Hardcoded Credential", sec_diags[0].message)
        self.assertIn("os.environ.get", sec_diags[0].auto_remediation.unified_diff)

    def test_hardware_trojan_test_port_detection(self):
        """CIRC-SEC-006: Unauthenticated JTAG/Scan chain nets driving internal gates should be flagged."""
        netlist = {
            "module": "secure_crypt_unit",
            "gates": {
                "key_reg_0": {"type": "DFF"},
                "key_reg_1": {"type": "DFF"},
            },
            "nets": {
                "jtag_tms_in": {
                    "drivers": ["PAD_JTAG_TMS"],
                    "sinks": ["key_reg_0", "key_reg_1"],
                }
            },
            "timing_paths": []
        }
        diags = _analyze_phase2_circuit(netlist)
        sec_diags = [d for d in diags if d.rule_id == "CIRC-SEC-006"]
        self.assertGreaterEqual(len(sec_diags), 1)
        self.assertEqual(sec_diags[0].severity, "CRITICAL")
        self.assertIn("Hardware Security", sec_diags[0].message)

    def test_security_defense_posture_audit(self):
        """Verify Defensive Posture score calculation and actionable directives."""
        # Clean guarded code
        clean_code = (
            "import os\n"
            "def safe_read(filepath):\n"
            "    real = os.path.realpath(filepath)\n"
            "    if not real.startswith(os.path.realpath('/safe')):\n"
            "        raise PermissionError('traversal')\n"
            "    if real is not None:\n"
            "        with open(real) as f:\n"
            "            return f.read()\n"
        )
        audit_clean = PragmaticAnalyzer.audit_security_defense(clean_code, [])
        self.assertIn(audit_clean["defensive_grade"], ("A+", "A"))
        self.assertEqual(audit_clean["security_vulnerabilities"], 0)

        # Vulnerable code with command injection and taint
        vulnerable_code = "import os\nos.system('echo ' + input())"
        diags = _analyze_phase1_code(vulnerable_code, "python")
        audit_vuln = PragmaticAnalyzer.audit_security_defense(vulnerable_code, diags)
        self.assertIn(audit_vuln["defensive_grade"], ("C", "F"))
        self.assertGreater(len(audit_vuln["directives"]), 0)

    def test_web_defensive_http_headers(self):
        """Verify web server enforces defense-in-depth HTTP security headers."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertIn("default-src 'self'", res.headers.get("Content-Security-Policy", ""))
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_payload_size_defensive_limit(self):
        """Verify web server protects against oversized memory exhaustion DoS."""
        oversized_data = json.dumps({"source_code": "a" * (3 * 1024 * 1024)})  # 3MB > 2MB limit
        res = self.client.post("/api/analyze/code", data=oversized_data, content_type="application/json")
        self.assertEqual(res.status_code, 413)

    def test_google_defense_headers(self):
        """Verify web server enforces Google production defense headers (gws, HSTS, COOP, CORP, strict CSP)."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("Server"), "gws")
        self.assertIn("max-age=31536000", res.headers.get("Strict-Transport-Security", ""))
        self.assertEqual(res.headers.get("Cross-Origin-Opener-Policy"), "same-origin")
        self.assertEqual(res.headers.get("Cross-Origin-Resource-Policy"), "same-origin")
        csp = res.headers.get("Content-Security-Policy", "")
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)

    def test_google_defense_unsupported_media_type(self):
        """Verify Google Defense rejects non-JSON payloads on JSON endpoints with HTTP 415."""
        res = self.client.post(
            "/api/analyze/code",
            data="<xml>bad_payload</xml>",
            content_type="application/xml"
        )
        self.assertEqual(res.status_code, 415)

    def test_google_defense_null_byte_protection(self):
        """Verify Google Defense blocks null byte URL/query string injection with HTTP 400."""
        res = self.client.get("/?param=\x00bad")
        self.assertEqual(res.status_code, 400)

    def test_google_defense_sanitizer_catalog(self):
        """Verify all 15 production rules have Google Sanitizer & Defense standards assigned."""
        for rule_id, rule in ALL_RULES.items():
            self.assertTrue(hasattr(rule, "google_defense_standard"))
            self.assertGreater(len(rule.google_defense_standard), 0)
            self.assertIn("Google", rule.google_defense_standard)

    def test_google_defense_posture_profile(self):
        """Verify PragmaticAnalyzer includes Google BeyondCorp profile."""
        audit = PragmaticAnalyzer.audit_security_defense("a = 1", [])
        self.assertIn("google_defense_profile", audit)
        profile = audit["google_defense_profile"]
        self.assertIn("Google BeyondCorp", profile["architecture"])
        self.assertEqual(profile["zero_trust_status"], "VERIFIED_SECURE")

    def test_google_access_blocked(self):
        """Verify Google crawlers and bots are strictly blocked with HTTP 403 Forbidden."""
        # 1. Googlebot
        res = self.client.get("/", headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"})
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json["shield_status"], "GOOGLE_ACCESS_FORBIDDEN")

        # 2. Google-InspectionTool
        res = self.client.get("/api/rules", headers={"User-Agent": "Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)"})
        self.assertEqual(res.status_code, 403)

        # 3. Google header signature
        res = self.client.get("/", headers={"User-Agent": "NormalBrowser/1.0", "X-Goog-Channel-Token": "secret"})
        self.assertEqual(res.status_code, 403)

        # 4. Standard browser passes through normally
        res_ok = self.client.get("/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        self.assertEqual(res_ok.status_code, 200)

    def test_robots_txt_disallows_google(self):
        """Verify robots.txt explicitly disallows Googlebot and search indexers."""
        res = self.client.get("/robots.txt")
        self.assertEqual(res.status_code, 200)
        self.assertIn("User-agent: Googlebot", res.data.decode("utf-8"))
        self.assertIn("Disallow: /", res.data.decode("utf-8"))

    def test_x_robots_tag_anti_indexing_header(self):
        """Verify X-Robots-Tag header prevents Google indexing and caching."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        robots_tag = res.headers.get("X-Robots-Tag", "")
        self.assertIn("noindex", robots_tag)
        self.assertIn("nofollow", robots_tag)
        self.assertIn("noarchive", robots_tag)


if __name__ == "__main__":
    unittest.main()


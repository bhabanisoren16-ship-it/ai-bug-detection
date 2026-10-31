import json
import time
import urllib.request

def test_endpoints():
    print("=" * 78)
    print("  WEBSITE END-TO-END NETWORK & API EFFICIENCY TEST")
    print("=" * 78)

    endpoints = [
        ("Local Dashboard (/)       ", "http://127.0.0.1:5000/"),
        ("Local Rules (/api/rules)  ", "http://127.0.0.1:5000/api/rules"),
        ("Local Agans Rules API     ", "http://127.0.0.1:5000/api/agans-rules"),
        ("Production Dashboard (/)  ", "https://ai-bugdetection.vercel.app/"),
        ("Production Rules API      ", "https://ai-bugdetection.vercel.app/api/rules"),
        ("Production Agans Rules API", "https://ai-bugdetection.vercel.app/api/agans-rules"),
    ]

    for label, url in endpoints:
        try:
            t0 = time.perf_counter()
            req = urllib.request.Request(url, headers={"User-Agent": "EfficiencyTester/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                code = resp.status
                body = resp.read()
                headers = dict(resp.headers)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            print(f"  {label}: HTTP {code} OK | {elapsed_ms:7.2f} ms | Payload: {len(body):6d} bytes")
        except Exception as exc:
            print(f"  {label}: FAILED -> {exc}")

    print("\n" + "-" * 78)
    print("  POST API ANALYSIS PERFORMANCE (PAYLOAD SCANNING)")
    print("-" * 78)

    # 1. Code scan payload
    code_payload = json.dumps({
        "source_code": (
            "def unsafe_worker(user_cmd, filename):\n"
            "    import os\n"
            "    os.system('echo ' + user_cmd)\n"
            "    with open('/var/data/' + filename) as f:\n"
            "        return f.read()\n"
        ),
        "language": "python"
    }).encode("utf-8")

    # Local POST
    t0 = time.perf_counter()
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/analyze/code",
        data=code_payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        code_res = json.loads(resp.read().decode("utf-8"))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    print(f"  Local POST /api/analyze/code     : HTTP 200 OK | {elapsed_ms:7.2f} ms | Bugs: {len(code_res.get('highlights', []))} localized")

    # Production POST
    t0 = time.perf_counter()
    req = urllib.request.Request(
        "https://ai-bugdetection.vercel.app/api/analyze/code",
        data=code_payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        code_res_prod = json.loads(resp.read().decode("utf-8"))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    print(f"  Production POST /api/analyze/code: HTTP 200 OK | {elapsed_ms:7.2f} ms | Bugs: {len(code_res_prod.get('highlights', []))} localized")

    # 2. Circuit scan payload
    circuit_payload = json.dumps({
        "gates": [
            {"id": "G1", "type": "AND", "inputs": ["in1", "fb"], "output": "mid"},
            {"id": "G2", "type": "NOT", "inputs": ["mid"], "output": "fb"}
        ],
        "nets": [
            {"id": "in1", "drivers": ["P1"], "loads": ["G1"]},
            {"id": "mid", "drivers": ["G1"], "loads": ["G2"]},
            {"id": "fb",  "drivers": ["G2"], "loads": ["G1"]}
        ],
        "sta_paths": []
    }).encode("utf-8")

    # Local Circuit POST
    t0 = time.perf_counter()
    req = urllib.request.Request(
        "http://127.0.0.1:5000/api/analyze/circuit",
        data=circuit_payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        circ_res = json.loads(resp.read().decode("utf-8"))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    print(f"  Local POST /api/analyze/circuit  : HTTP 200 OK | {elapsed_ms:7.2f} ms | Bugs: {len(circ_res.get('highlights', []))} localized")

    # Production Circuit POST
    t0 = time.perf_counter()
    req = urllib.request.Request(
        "https://ai-bugdetection.vercel.app/api/analyze/circuit",
        data=circuit_payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        circ_res_prod = json.loads(resp.read().decode("utf-8"))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    print(f"  Production POST /api/analyze/circ: HTTP 200 OK | {elapsed_ms:7.2f} ms | Bugs: {len(circ_res_prod.get('highlights', []))} localized")

    print("=" * 78)

if __name__ == "__main__":
    test_endpoints()


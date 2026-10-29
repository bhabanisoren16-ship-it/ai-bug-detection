"""Sample buggy Python code with intentional bugs for testing.

This file contains patterns that the UnifiedBugHighlightEngine should detect.
Each function is annotated with the expected rule ID.
"""


# ── 1. Use-After-Free pattern (CODE-MEM-001) ─────────────────────────────────

def process_buffer(data):
    """Demonstrates use-after-free: buffer used after being freed."""
    buf = allocate(data)
    free_buf(buf)
    print(buf)  # BUG: use-after-free — buf accessed after free_buf()
    return buf   # BUG: second use-after-free


# ── 2. Division by Zero (CODE-NUM-003) ───────────────────────────────────────

def calculate_ratio(a, b):
    """Demonstrates division by zero with a variable known to be 0."""
    divisor = 0
    result = a / divisor  # BUG: divisor is 0
    return result


def modulo_zero():
    """Modulo by zero variant."""
    count = 0
    return 42 % count  # BUG: count is 0


# ── 3. Taint Injection — SQL (CODE-SEC-004) ──────────────────────────────────

def search_user():
    """SQL injection: unsanitized input flows to execute()."""
    user_input = input("Enter username: ")
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)  # BUG: tainted 'user_input' in query → execute()


# ── 4. Taint Injection — OS command (CODE-SEC-004) ───────────────────────────

def run_command():
    """Command injection: unsanitized input flows to eval()."""
    cmd = input("Enter expression: ")
    eval(cmd)  # BUG: tainted 'cmd' flows to eval()


# ── 5. Off-by-one (CODE-MEM-002 / LOGIC-006) ────────────────────────────────

def compare_neighbors(array):
    """Off-by-one: array[i+1] in range(len(array)) overflows on last iteration."""
    for i in range(len(array)):
        if array[i] > array[i + 1]:  # BUG: IndexError when i == len(array)-1
            array[i], array[i + 1] = array[i + 1], array[i]


# ── 6. Mutable Default Argument (CODE-STYLE-007) ────────────────────────────

def append_item(value, items=[]):
    """Mutable default: list is shared across calls."""
    items.append(value)
    return items


# ── 7. Bare Except (CODE-STYLE-008) ─────────────────────────────────────────

def risky_operation():
    """Bare except swallows all exceptions, including SystemExit."""
    try:
        do_something()
    except:
        pass  # BUG: bare except catches everything


# ── 8. Comparison to None with == (CODE-STYLE-009) ──────────────────────────

def check_value(x):
    """Should use 'is None' instead of '== None'."""
    if x == None:  # BUG: use 'is None'
        return "empty"
    return x


# ── 9. Data Race pattern (CODE-CON-005) — structural marker ─────────────────

import threading

shared_counter = 0

def increment():
    """Data race: shared_counter modified without lock by multiple threads."""
    global shared_counter
    for _ in range(100000):
        shared_counter += 1  # BUG: no lock, race condition


def start_threads():
    threads = [threading.Thread(target=increment) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ── Helper stubs (so the file parses without NameError at AST level) ─────────

def allocate(data):
    return data

def free_buf(buf):
    pass

def do_something():
    pass

cursor = type("Cursor", (), {"execute": staticmethod(lambda q: None)})()

"""
Vercel Serverless Function Entry Point for AI Bug Detection & Highlighting Dashboard.
"""

import sys
from pathlib import Path

# Add project root to Python module search path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from web.app import app

# Vercel serverless WSGI handler
# The 'app' symbol is automatically handled by @vercel/python

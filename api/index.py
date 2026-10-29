"""
Vercel Serverless Function Entry Point for AI Bug Detection & Highlighting Dashboard.
"""

import sys
import urllib.parse
from pathlib import Path

# Add project root to Python module search path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from web.app import app


class VercelPathFixMiddleware:
    """Restores the original request path from Vercel query or proxy headers."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # 1. Check if Vercel rewrite passed __path__ in query string
        query = environ.get("QUERY_STRING", "")
        if "__path__=" in query:
            qs = urllib.parse.parse_qs(query)
            if "__path__" in qs and qs["__path__"]:
                req_path = qs["__path__"][0]
                if not req_path.startswith("/"):
                    req_path = "/" + req_path
                environ["PATH_INFO"] = req_path
                # Clean up query string
                cleaned_qs = {k: v for k, v in qs.items() if k != "__path__"}
                environ["QUERY_STRING"] = urllib.parse.urlencode(cleaned_qs, doseq=True)
                return self.wsgi_app(environ, start_response)

        # 2. Check X-Forwarded-Uri
        raw_uri = environ.get("HTTP_X_FORWARDED_URI")
        if raw_uri and not raw_uri.startswith("/api/index"):
            environ["PATH_INFO"] = raw_uri.split("?")[0]
        else:
            path = environ.get("PATH_INFO", "")
            for prefix in ("/api/index.py", "/api/index"):
                if path.startswith(prefix):
                    rest = path[len(prefix):]
                    environ["PATH_INFO"] = rest if (rest and rest.startswith("/")) else ("/" + rest.lstrip("/"))
                    break

        return self.wsgi_app(environ, start_response)


# Wrap Flask WSGI app with Vercel path normalizer
app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

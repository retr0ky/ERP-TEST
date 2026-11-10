import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import app  # noqa: F401  (Vercel WSGI entrypoint)

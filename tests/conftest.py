import sys
import os

# Add the correct Python path for models/database/etc depending on where
# pytest is being run from:
# - Inside Docker: tests/ and models.py both live under /app, so the
#   parent of tests/ (i.e. /app itself) is the right path.
# - On the host: backend/ and tests/ are sibling folders, so we need
#   tests/../backend.
_here = os.path.dirname(os.path.abspath(__file__))
_candidates = [
    os.path.abspath(os.path.join(_here, '..')),           # docker: /app
    os.path.abspath(os.path.join(_here, '..', 'backend')),  # host: backend/
]
for _path in _candidates:
    if os.path.isdir(_path) and _path not in sys.path:
        sys.path.insert(0, _path)
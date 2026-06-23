import sys
import os

# Add the backend folder to Python's path so tests can import models, database etc.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
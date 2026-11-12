import sys
from pathlib import Path

# Make scripts/ importable as top-level modules in tests.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

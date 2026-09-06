"""Ensure tests import the repo's zn_gate, not any installed copy."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

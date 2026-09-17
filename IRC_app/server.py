#!/usr/bin/env python3
"""
RFeye IRC Server — entry point.

The implementation now lives in the rfeye_server/ package (models.py,
views.py, controllers.py, app.py) so API/protocol concerns are separated
from state and presentation. This file just keeps `python3 server.py`
working as before. security.py and wavutil.py stay where they are, at
the project root, alongside this file.
"""
from rfeye_server.app import run

if __name__ == "__main__":
    run()
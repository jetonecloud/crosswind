"""Crosswind's internals.

`terraform.py` is the only module in the package that starts a process, and
`workspace.py` is the only one that creates a file outside the output
directory the user asked for. Everything else is a pure function of data.
"""

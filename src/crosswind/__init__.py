"""Crosswind: a read-only Terraform drift checker.

Finds changes made outside Terraform in the resources Terraform already
manages, attributes them to a CloudTrail event where the evidence supports
it, scores them against a readable rule set, and recommends reverting the
change or updating the code. It never does either, and it never writes
anything to AWS, to your state, or to your working tree.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]

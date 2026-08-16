"""Settler test suite.

A package rather than a bare directory so that the shared builders in
``conftest`` are imported as ``settler.tests.conftest`` — an import a type
checker can follow. The pytest idiom of a top-level ``from conftest import ...``
relies on a sys.path entry that only exists while pytest is running, which makes
``mypy --strict`` unable to see any of it.
"""

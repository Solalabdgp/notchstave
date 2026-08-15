"""Tests for the deriver package.

A real package rather than a bare directory so that the shared test material in
``test_account_addresses`` (the throwaway account xpub and its five control
addresses) can be imported by the other modules instead of copy-pasted into
each of them. One definition of the test key means one place to check that it
is still the published throwaway one.
"""

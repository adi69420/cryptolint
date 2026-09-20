"""A TEST file (test_*.py) holding a verify=False, expected to down-tier.

Expected: REVIEW, marked in-test -- a self-signed/localhost cert in a test is
a defensible use. Not skipped, just quieter.
"""
import requests


# [REVIEW in-test] the same bug as the HIGH cases, inside a test file
def test_against_local_https():
    return requests.get("https://localhost:8443", verify=False)

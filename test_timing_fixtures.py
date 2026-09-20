"""A TEST file (name matches test_*.py) holding a copy of a HIGH case.

Expected: down-tiered one step to REVIEW and marked in-test.
Do not edit to make the detector pass.
"""


# [REVIEW in-test] a copy of the user_token HIGH case, in a test file
def test_token_compare(user_token, real_token):
    assert user_token == real_token


# [LOW in-test] a copy of a REVIEW (collision) case, down-tiered
def test_mac_compare(computed_mac, expected_mac):
    assert computed_mac != expected_mac

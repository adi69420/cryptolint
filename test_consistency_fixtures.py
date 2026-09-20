"""TEST file exercising the T1-3 split: which detectors down-tier here.

DOWN-TIER (fixture-plausible): swallowed-exception, secret-sink, weak-random,
  timing-compare, tls-verify, hardcoded-secret
STAY HIGH (wrong-regardless): ecb-mode, weak-hash
Do not edit to make the detector pass.
"""
import hashlib
import logging
import random
from Crypto.Cipher import AES

logger = logging.getLogger(__name__)


# [#1 REVIEW in-test] a swallow in a test is often a deliberate error-path probe
def test_swallow():
    try:
        work()
    except Exception:
        pass


# [#3 REVIEW in-test] logging a fixture secret is low-risk scaffolding
def test_logs_secret(password):
    logger.error("pw=%s", password)


# [#4 REVIEW in-test] a test token is a fixture
def test_token():
    token = random.randbytes(16)
    return token


# [#6 HIGH in-test] a broken cipher mode is broken in a test too
def test_ecb(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)


# [#7 HIGH in-test] a broken hash primitive is broken in a test too
def test_weak_hash(password):
    return hashlib.md5(password).hexdigest()


def work(): ...

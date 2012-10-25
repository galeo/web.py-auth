# −*− coding: utf−8 −*−
"""
Functions to generate and check tokens for the password
reset mechanism.
"""

import web
import sha
from time import time


def make_token(user):
    """Returns a token that can be used once to do a password reset
    for the given user.
    """
    return _make_token(user, int(time()))


def check_token(user, token, expire_after):
    """ Check that a password reset token is correct and still valid
    for a given user. "expire_after" must be in hours.
    """
    # Parse the tokem
    try:
        ts_b36, hash = token.split("$")
    except ValueError:
        return False

    try:
        ts = int(ts_b36, 36)
    except ValueError:
        return False

    # Check that the user/timestamp has not been tampered with
    if _make_token(user, ts) != token:
        return False

    # Check the timestamp is within limit
    if (time() - ts) > (expire_after * 3600):
        return False

    return True


def _make_token(user, timestamp):
    ts_b36 = web.to36(timestamp)

    # By hashing on the internal state of the user and using state
    # that is sure to change (the password hash and the last_login)
    # we produce a hash that will be invalid as soon as it --or the old
    # password-- is used.
    # By hashing also a secret key the system cannot be subverted
    # even if the database is compromised.
    items = [
        web.config.session_parameters.secret_key,
        unicode(user.user_id),
        u'@', user.user_password,
        unicode(user.user_last_login),
        unicode(timestamp)]
    hash = sha.new(''.join(items)).hexdigest()
    return "%s$%s" % (ts_b36, hash)

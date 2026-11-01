"""Authentication helpers shared by startup, HTTP, and SOCKS5 flows."""

import hmac

from werkzeug.security import check_password_hash, generate_password_hash


PASSWORD_HASH_PREFIX = '{WZ-SCRYPT}'
UNCHANGED_PASSWORD = '__PROXYCAT_PASSWORD_UNCHANGED__'
DEFAULT_PROXY_PASSWORD = '123456'


def hash_proxy_password(password):
    """Return a tagged scrypt hash for a proxy password.

    Args:
        password: Plaintext password supplied during bootstrap or user updates.

    Returns:
        A tagged hash suitable for storage in the Users configuration section.

    Raises:
        ValueError: If Werkzeug cannot derive a password hash.
    """
    return PASSWORD_HASH_PREFIX + generate_password_hash(str(password), method='scrypt')


def verify_proxy_password(configured_password, supplied_password):
    """Verify a supplied proxy password against stored credentials.

    Args:
        configured_password: Stored tagged hash or legacy plaintext password.
        supplied_password: Password received from an inbound proxy client.

    Returns:
        True when the credentials match; otherwise False, including malformed hashes.
    """
    if configured_password is None:
        return False

    configured_password = str(configured_password)
    supplied_password = str(supplied_password)
    if configured_password.startswith(PASSWORD_HASH_PREFIX):
        try:
            return check_password_hash(
                configured_password[len(PASSWORD_HASH_PREFIX):], supplied_password
            )
        except (ValueError, TypeError):
            return False

    return hmac.compare_digest(configured_password, supplied_password)

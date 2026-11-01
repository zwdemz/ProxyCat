"""Initialize private runtime credentials without rewriting the user's INI file."""

import os
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from modules.auth import hash_proxy_password

INITIAL_CREDENTIALS_FILENAME = 'initial_credentials.txt'
TOKEN_ROTATION_SECONDS = 15 * 24 * 60 * 60
_LOCK = threading.RLock()


@contextmanager
def _credential_lock(path):
    """Hold a cross-process lock next to the private credentials file.

    Args:
        path: Credential file path. Its parent must already exist.
    Yields:
        Control while the lock is held; filesystem failures propagate as OSError.
    """
    with _LOCK, open(str(path) + '.lock', 'a+b') as handle:
        handle.seek(0, os.SEEK_END)
        if not handle.tell():
            handle.write(b'\0')
            handle.flush()
        handle.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def initialize_credentials(config, config_file):
    """Fill missing authentication values from a private, persistent sidecar.

    Args:
        config: Loaded configuration mapping, updated in memory only.
        config_file: INI path used to locate initial_credentials.txt.
    Returns:
        The same mapping, with environment credentials taking precedence.
    Raises:
        OSError: If required credentials cannot be read or securely persisted.
        ValueError: If password hashing fails.
    """
    environment_token = os.environ.get('PROXYCAT_MANAGEMENT_TOKEN', '').strip()
    if environment_token:
        config['token'] = environment_token
    if os.environ.get('PROXYCAT_DISABLE_CREDENTIAL_BOOTSTRAP', '').lower() == 'true':
        return config
    users = {name: password for name, password in config.get('Users', {}).items()
             if name.strip() and password}
    proxy_environment = bool(os.environ.get('PROXYCAT_PROXY_USERNAME', '').strip()
                             or os.environ.get('PROXYCAT_PROXY_PASSWORD', ''))
    need_token = not str(config.get('token', '')).strip()
    config['_management_token_generated'] = need_token
    config['_management_token_expires_at'] = None
    need_user = (str(config.get('require_proxy_auth', 'true')).lower() == 'true'
                 and not users and not proxy_environment)
    if not need_token and not need_user:
        return config

    path = Path(config_file).resolve().parent / INITIAL_CREDENTIALS_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    with _credential_lock(path):
        saved = {}
        if path.exists():
            for line in path.read_text(encoding='utf-8').splitlines():
                label, separator, value = line.partition(': ')
                if separator:
                    saved[label] = value
        changed = False
        if need_token:
            now = time.time()
            try:
                generated_at = float(saved.get('Management token generated at', ''))
                valid_timestamp = 0 < generated_at <= now
            except ValueError:
                valid_timestamp = False
            if not valid_timestamp:
                generated_at = now
                changed = True
            if not saved.get('Management token') or now >= generated_at + TOKEN_ROTATION_SECONDS:
                saved['Management token'] = secrets.token_urlsafe(32)
                generated_at = now
                changed = True
            saved['Management token generated at'] = str(generated_at)
            config['token'] = saved['Management token']
            config['_management_token_expires_at'] = generated_at + TOKEN_ROTATION_SECONDS
        if need_user:
            if not saved.get('Proxy password'):
                saved['Proxy username'] = 'proxycat'
                saved['Proxy password'] = secrets.token_urlsafe(24)
                changed = True
            if not saved.get('Proxy password hash'):
                saved['Proxy password hash'] = hash_proxy_password(saved['Proxy password'])
                changed = True
            users[saved['Proxy username']] = saved['Proxy password hash']
            config['Users'] = users
        if changed:
            descriptor, temporary = tempfile.mkstemp(prefix='.credentials-', dir=path.parent)
            try:
                with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                    handle.write('ProxyCat initial credentials\nKeep this file private; it is reused on restart.\n\n')
                    handle.writelines(f'{label}: {value}\n' for label, value in saved.items())
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.remove(temporary)
            print(f'[ProxyCat] Credentials file: {path}')
    return config

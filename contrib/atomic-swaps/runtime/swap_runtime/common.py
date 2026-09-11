"""Bounded input, durable private files and process-held session ownership."""
import json
import os
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def strict_json(raw, **kwargs):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    def no_constant(_):
        raise ValueError('Nonfinite JSON number')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant, **kwargs)


def integer(value, name, minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid ' + name)
    return value


def hex_bytes(value, size, name):
    if type(value) is not str:
        raise ValueError('Invalid ' + name)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError('Invalid ' + name) from None
    if len(raw) != size or raw.hex() != value:
        raise ValueError('Noncanonical ' + name)
    return raw


def sync_directory(path):
    # Windows SQLite/file fsync is used; Python cannot fsync a directory handle there.
    if os.name != 'nt':
        fd = os.open(Path(path), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def private_read(path, maximum=65536):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Regular private file required')
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        raise ValueError('Private file must have owner-only permissions')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('Private file exceeds size bound')
    return raw


def new_private_file(path, data):
    """Create without overwriting an existing key, backup or export."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


class SessionLock:
    """Hold the OS lock for the entire open session; never delete a live lock file."""
    def __init__(self, path):
        self.path = Path(str(Path(path).resolve()) + '.lock')
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        self.stream = os.fdopen(fd, 'r+b', buffering=0)
        if self.path.stat().st_size == 0:
            self.stream.write(b'\0')
        self.stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise ValueError('This session is already open in another process') from None

    def close(self):
        if self.stream.closed:
            return
        try:
            self.stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()

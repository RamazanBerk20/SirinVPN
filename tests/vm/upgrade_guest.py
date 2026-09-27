"""Private backup/profile checks; runs only in the owned disposable Linux guest."""
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import select
import signal
import sys
import tempfile
import time

CLI = '/usr/bin/sirinvpn'
CONFIG = Path.home() / '.config/sirinvpn'
BACKUP = Path.home() / 'upgrade-backup'


def prompt(arguments, password, prompts, environment):
    pid, terminal = pty.fork()
    if pid == 0:
        os.execve(CLI, [CLI, '--json', *arguments], environment)
    received, deadline = b'', time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            if not select.select([terminal], [], [], .2)[0]:
                continue
            try:
                block = os.read(terminal, 8192)
            except OSError:
                break
            if not block:
                break
            received += block
            assert len(received) < 32768
            if prompts and prompts[0] in received:
                os.write(terminal, (password + '\n').encode())
                prompts.pop(0)
                received = b''
        else:
            raise RuntimeError('Backup prompt timeout')
        _, status = os.waitpid(pid, 0)
        pid = None
        assert os.waitstatus_to_exitcode(status) == 0 and not prompts, 'Backup command failed'
    finally:
        os.close(terminal)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def backup(create):
    import subprocess
    original = json.loads((CONFIG / 'servers.json').read_text())['servers'][0]
    if create:
        BACKUP.mkdir(mode=0o700)
        password = secrets.token_hex(16)
        descriptor = os.open(BACKUP / 'password', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(password)
            output.flush()
            os.fsync(output.fileno())
        for directory in (BACKUP, BACKUP.parent):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        prompt(['server', 'export', original['id'], '--output', str(BACKUP / 'identity.sirin'),
                '--confirm-sensitive-export'], password,
               [b'Backup password (hidden, minimum 12 characters): ', b'Repeat backup password: '], dict(os.environ))
    password = (BACKUP / 'password').read_text()
    # Never connect the restored copy while the original device identity exists.
    with tempfile.TemporaryDirectory(prefix='restore-', dir=BACKUP) as directory:
        environment = dict(os.environ, XDG_CONFIG_HOME=directory)
        subprocess.run([CLI, 'storage', 'allow-private-file'], env=environment,
                       check=True, capture_output=True, timeout=15)
        prompt(['server', 'import', '--input', str(BACKUP / 'identity.sirin')], password,
               [b'Backup password (hidden): '], environment)
        restored_dir = Path(directory) / 'sirinvpn'
        restored = json.loads((restored_dir / 'servers.json').read_text())['servers'][0]
        old_reference = original.pop('identity_reference')
        new_reference = restored.pop('identity_reference')
        assert original == restored, 'Restored profile differs'
        assert json.loads((CONFIG / 'secrets' / (old_reference+'.json')).read_text()) == \
               json.loads((restored_dir / 'secrets' / (new_reference+'.json')).read_text()), 'Restored identity differs'
    print(json.dumps({'encrypted_backup_restore': True, 'profile_and_identity_equal': True}))


def snapshot():
    paths = [CONFIG / 'servers.json', *sorted((CONFIG / 'secrets').glob('*'))]
    digest = hashlib.sha256()
    assert len(paths) > 1
    for path in paths:
        assert path.is_file() and not path.is_symlink()
        digest.update(path.name.encode() + b'\0' + path.read_bytes() + b'\0')
    print(json.dumps({'files': len(paths), 'sha256': digest.hexdigest()}))


if __name__ == '__main__':
    assert Path('/etc/sirinvpn-acceptance-fixture').is_file() and os.geteuid() != 0
    if sys.argv[1] == 'snapshot':
        snapshot()
    else:
        assert sys.argv[1] in ('backup-create', 'backup-verify')
        backup(sys.argv[1] == 'backup-create')

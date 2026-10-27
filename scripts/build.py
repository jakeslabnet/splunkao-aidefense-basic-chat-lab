"""Build reproducible CodeZip archives; never copies credentials or local environments."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / 'build'


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def archive(source: Path, destination: Path) -> str:
    files = sorted(path for path in source.rglob('*') if path.is_file()
                   and '__pycache__' not in path.parts and path.suffix != '.pyc')
    total = sum(path.stat().st_size for path in files)
    if total > 750 * 1024 * 1024:
        raise ValueError('Package exceeds AgentCore uncompressed size limit')
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in files:
            if path.suffix == '.so':
                header = path.read_bytes()[:20]
                if header[:4] != b'\x7fELF' or struct.unpack('<H', header[18:20])[0] != 183:
                    raise ValueError(f'Native module is not Linux ARM64: {path.name}')
            info = zipfile.ZipInfo(path.relative_to(source).as_posix(), (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, path.read_bytes())
    if destination.stat().st_size > 250 * 1024 * 1024:
        raise ValueError('Archive exceeds compressed deployment size limit')
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main() -> None:
    BUILD.mkdir(exist_ok=True)
    package = BUILD / 'agent-package'
    if package.exists():
        shutil.rmtree(package)
    package.mkdir()
    # Python 3.13 CodeZip uses Amazon Linux 2023 (glibc 2.34). Match the lock
    # target so ARM64 wheels such as google-re2 are eligible without compiling.
    run('uv', 'pip', 'install', '--python-platform', 'aarch64-manylinux_2_34',
        '--python-version', '3.13', '--target', str(package), '--only-binary=:all:',
        '--require-hashes', '--cache-dir', '/private/tmp/agentcore-chat-uv-cache',
        '-r', 'agent/requirements.txt')
    for source in (ROOT / 'agent').rglob('*.py'):
        relative = source.relative_to(ROOT / 'agent')
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        target = package / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    agent_hash = archive(package, BUILD / 'agent.zip')
    run('npm', '--prefix', 'api', 'run', 'package')
    shutil.copyfile(ROOT / 'api/dist/api.zip', BUILD / 'api.zip')
    api_hash = hashlib.sha256((BUILD / 'api.zip').read_bytes()).hexdigest()
    run('npm', '--prefix', 'web', 'run', 'build')
    manifest = {'agentKey': f'releases/{agent_hash}/agent.zip',
                'apiKey': f'releases/{api_hash}/api.zip',
                'agentSha256': agent_hash, 'apiSha256': api_hash}
    (BUILD / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'agentBytes': (BUILD / 'agent.zip').stat().st_size,
                      'apiBytes': (BUILD / 'api.zip').stat().st_size,
                      'manifest': manifest}, indent=2))


if __name__ == '__main__':
    main()

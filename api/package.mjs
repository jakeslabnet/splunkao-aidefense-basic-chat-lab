import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cwd = fileURLToPath(new URL('.', import.meta.url));
// Fixed ordering, timestamps, and permissions make identical releases produce identical S3 artifact hashes.
const script = `
from pathlib import Path
import zipfile
root = Path.cwd()
dependencies = root / 'node_modules'
if not dependencies.is_dir():
    raise RuntimeError('Run npm ci in api/ first')
destination = root / 'dist' / 'api.zip'
destination.parent.mkdir(exist_ok=True)
files = [root / 'index.mjs', root / 'core.mjs', root / 'package.json']
files += [path for path in dependencies.rglob('*') if path.is_file() and path.suffix != '.map']
with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
    for path in sorted(files):
        info = zipfile.ZipInfo(path.relative_to(root).as_posix(), (2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        output.writestr(info, path.read_bytes())
`;
const result = spawnSync('python3', ['-c', script], { cwd, stdio: 'inherit' });
if (result.status !== 0) throw new Error('API packaging failed. Run npm ci in api/ first.');
console.log('Created api/dist/api.zip (handler: index.handler).');

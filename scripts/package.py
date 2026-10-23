"""Build a standalone release containing the checksum-pinned server core."""
import argparse
import hashlib
import io
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tuna_dns.backend import ASSET_SHA256


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', required=True, type=Path)
    args = parser.parse_args()
    core = args.core.read_bytes()
    if hashlib.sha256(core).hexdigest() != ASSET_SHA256:
        raise SystemExit('Core SHA256 mismatch')
    name = 'tuna-dns-tunnel-0.1.0-rc2'
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    target = output / (name + '.tar.gz')
    files = [ROOT / file for file in ('README.md', 'LICENSE', 'VALIDATION.md', 'CHANGELOG.md', 'install.sh')]
    for folder in ('tuna_dns', 'bin', 'licenses', 'tests', 'scripts'):
        files.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    with tarfile.open(target, 'w:gz') as archive:
        for path in sorted(files):
            relative = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            if path.suffix in ('.py', '.md', '.sh', '.txt') or relative in ('bin/tuna-dns', 'LICENSE'):
                data = data.decode('utf-8-sig').replace('\r\n', '\n').encode()
            info = tarfile.TarInfo(name + '/' + relative)
            info.size = len(data)
            info.mode = 0o755 if relative in ('install.sh', 'bin/tuna-dns') else 0o644
            archive.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo(name + '/assets/masterdns-amd64.tar.gz')
        info.size, info.mode = len(core), 0o644
        archive.addfile(info, io.BytesIO(core))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (output / 'SHA256SUMS').write_text(f'{digest}  {target.name}\n', encoding='ascii')
    print(target)
    print(digest)


if __name__ == '__main__':
    main()

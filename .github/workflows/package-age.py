#!/usr/bin/env python3
"""Reject young registry versions in frozen npm/pnpm lockfiles before acquisition."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import gzip
import io
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

MINUTES = 10080

# Existing internal source archives, pinned to reviewed immutable commits.
# These are source dependencies, not registry publications. No moving refs.
SOURCE_PINS = {
    '@crnkl/burn-verification@https://codeload.github.com/crinkl-protocol/crinkl-burn-verification/tar.gz/66ad5263b680c3f86c98f3513559121c8bf24dcd',
    '@crnkl/zk-verifier@https://codeload.github.com/crinkl-protocol/crinkl-zk-verifier/tar.gz/4e7e8b7ee43f9d06b1f4c2847a2182e85b389dbe',
}


def packages(path):
    if path.name == 'package-lock.json':
        data = json.loads(path.read_text())
        if data.get('lockfileVersion') not in (2, 3):
            raise ValueError('require npm lockfile version 2 or 3')
        result = set()
        for location, package in data['packages'].items():
            if not location or package.get('link'):
                continue
            resolved = package.get('resolved', '')
            if resolved.startswith('file:'):
                continue
            if not resolved.startswith('https://registry.npmjs.org/'):
                raise ValueError(f'unreviewed non-registry dependency: {location}')
            name = package.get('name') or location.rsplit('node_modules/', 1)[-1]
            result.add((name, package['version']))
        return result
    text = path.read_text()
    if not re.search(r"^lockfileVersion: ['\"]?9\.0['\"]?\s*$", text, re.M):
        raise ValueError('require pnpm lockfile version 9.0')
    section = text.partition('\npackages:\n')[2].split('\nsnapshots:\n')[0]
    result = set()
    for line in section.splitlines():
        if not re.match(r'^  \S', line):
            continue
        key = line.strip().removesuffix(':').strip("'\"")
        if key in SOURCE_PINS:
            continue
        name, version = key.rsplit('@', 1)
        if version.startswith(('file:', 'link:', 'workspace:')):
            continue
        version = version.split('(', 1)[0]
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?', version):
            raise ValueError(f'unreviewed non-registry dependency: {key}')
        result.add((name, version))
    if not result:
        raise ValueError('lockfile has no recognized registry package entries')
    return result


def check_versions(name_versions, fetch, now):
    by_name = {}
    for name, version in name_versions:
        by_name.setdefault(name, set()).add(version)
    cutoff = now - timedelta(minutes=MINUTES)

    def check(item):
        name, versions = item
        metadata = fetch(name)
        for version in sorted(versions):
            stamp = metadata.get('time', {}).get(version)
            if not stamp or version not in metadata.get('versions', {}):
                raise ValueError(f'no publication proof for {name}@{version}')
            published = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if published.tzinfo is None or published > cutoff:
                raise ValueError(f'{name}@{version} is newer than {MINUTES} minutes')

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(check, sorted(by_name.items())))


def registry_metadata(name):
    request = Request('https://registry.npmjs.org/' + quote(name, safe='@'),
                      headers={'Accept': 'application/json', 'Accept-Encoding': 'gzip'})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
                if len(raw) > 32 * 1024 * 1024:
                    raise ValueError(f'registry response too large for {name}')
                if response.headers.get('Content-Encoding') == 'gzip':
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(64 * 1024 * 1024 + 1)
                if len(raw) > 64 * 1024 * 1024:
                    raise ValueError(f'registry metadata too large for {name}')
                return json.loads(raw)
        except HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504):
                raise ValueError(f'no registry publication proof for {name}: HTTP {error.code}') from None
        except (URLError, TimeoutError):
            pass
        if attempt < 2:
            time.sleep(2 ** attempt)
    raise ValueError(f'no registry publication proof for {name} after three attempts')


def main():
    manager = sys.argv[1] if len(sys.argv) > 1 else ''
    if manager not in ('', 'npm', 'pnpm'):
        raise ValueError('expected npm or pnpm')
    names = ('package-lock.json',) if manager == 'npm' else ('pnpm-lock.yaml',) if manager == 'pnpm' else ('pnpm-lock.yaml', 'package-lock.json')
    root = Path.cwd()
    while not any((root / name).exists() for name in names):
        if root.parent == root:
            raise ValueError('no committed npm/pnpm lockfile found')
        root = root.parent
    matches = [root / name for name in names if (root / name).exists()]
    if len(matches) != 1:
        raise ValueError('multiple lock formats: specify npm or pnpm')
    path = matches[0]
    selected = packages(path)
    check_versions(selected, registry_metadata, datetime.now(timezone.utc))
    print(f'[package-age] PASS {len(selected)} locked registry versions >= {MINUTES} minutes')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'[package-age] REFUSED: {error}', file=sys.stderr)
        sys.exit(1)

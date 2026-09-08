"""Read-only source, dependency, toolchain and local evidence identity audit."""
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import sys
import tarfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent
EVIDENCE = ROOT.parent.parent
TOOLS = EVIDENCE / 'swap-integration-v03/external-tools/platform-tools'


def identity(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


def main():
    lock = tomllib.loads((ROOT / 'Cargo.lock').read_text(encoding='utf-8'))
    packages = [p for p in lock['package'] if p.get('source', '').startswith('registry+')]
    dependencies = []
    failures = []
    compared_files = 0
    for p in packages:
        label = f"{p['name']}-{p['version']}"
        archives = list((ROOT / 'cargo-home/registry/cache').glob(f'*/{label}.crate'))
        unpacked = list((ROOT / 'cargo-home/registry/src').glob(f'*/{label}'))
        if len(archives) != 1 or len(unpacked) != 1:
            failures.append(f'{label}: missing or ambiguous cache/source')
            continue
        actual = identity(archives[0])
        if actual['sha256'] != p['checksum']:
            failures.append(f'{label}: archive checksum mismatch')
        checked = 0
        with tarfile.open(archives[0], 'r:gz') as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                relative = pathlib.PurePosixPath(member.name)
                if relative.parts[0] != label or '..' in relative.parts:
                    raise AssertionError('unexpected archive layout')
                path = unpacked[0].joinpath(*relative.parts[1:])
                stream = archive.extractfile(member)
                expected = hashlib.file_digest(stream, 'sha256').hexdigest()
                if not path.is_file() or identity(path)['sha256'] != expected:
                    failures.append(f'{label}: unpacked source mismatch {relative}')
                checked += 1
        compared_files += checked
        dependencies.append(dict(name=p['name'], version=p['version'], archive=actual, source_files_checked=checked))

    selected = [TOOLS / p for p in (
        'rust/bin/cargo.exe', 'rust/bin/rustc.exe',
        'rust/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe',
        'llvm/bin/llvm-readelf.exe', 'version.md')]
    selected += list((TOOLS / 'rust/bin').glob('*.dll'))
    selected += list((TOOLS / 'rust/lib/rustlib/sbpfv3-solana-solana/lib').glob('*'))
    tool_files = {str(p.relative_to(TOOLS)).replace('\\', '/'): identity(p) for p in selected if p.is_file()}
    original_test = EVIDENCE / 'swap-localnet-v04/test_solana_vm.py'
    if (ROOT / 'test_solana_vm.py').read_bytes() != original_test.read_bytes():
        failures.append('original VM tests changed')
    hashes = {name: identity(ROOT / name) for name in ('src/lib.rs', 'Cargo.toml', 'Cargo.lock',
              'solana_escrow.so', 'test_solana_vm.py', 'test_differential.py')}
    if hashes['solana_escrow.so']['sha256'] != '30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7':
        failures.append('candidate identity mismatch')
    comparison = json.loads((ROOT / 'repro-comparison.json').read_text(encoding='utf-8-sig'))
    if not comparison['target-repro-02']['whole_elf_identical']:
        failures.append('fresh rebuild identity mismatch')
    result = dict(status='PASS' if not failures else 'FAIL', failures=failures, sources=hashes,
        baseline={name: identity(EVIDENCE / 'swap-localnet-v04' / name) for name in
                  ('solana_escrow.c', 'solana_profile.h', 'solana_escrow.so', 'test_solana_vm.py')},
        dependency_count=len(packages), dependency_archive_checksums_match=not any('archive checksum' in f for f in failures),
        unpacked_source_files_checked=compared_files, dependencies=dependencies,
        toolchain_files=tool_files, python=dict(executable=sys.executable, version=platform.python_version(),
        platform=platform.platform(), solders=importlib.metadata.version('solders')),
        evidence=['build-dev02.log', 'vm-original13.log', 'vm-differential-dev01.log',
                  'target-repro-01/result.json', 'target-repro-02/result.json', 'repro-comparison.json'],
        bounds='Local artifact/input identity and retained local test reports; not independent runtime execution, formal equivalence, reproducibility across paths/hosts or RPC/deployment qualification.')
    print(json.dumps(result, indent=2))
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())

"""Bounded actual XDS/Solana run, pinned to the reviewed program and native build."""
import argparse, datetime, hashlib, importlib.metadata, json, os, pathlib, subprocess, sys, time

BASE = pathlib.Path('/var/lib/discrete-swap-lab')
STAGE = BASE / 'rpc-v3-stage'
PACKAGE = STAGE / 'paired-rpc-harness'
NATIVE = BASE / 'qualification-v05'
CGROUP = pathlib.Path('/sys/fs/cgroup/discrete.slice/discrete-swap.slice/discrete-swap-solana.slice')
EXPECTED_MANIFEST = 'c5a745f258406be5cbbeb19937f9c6db88ccb4708a48fe0166863d7925864e02'
EXPECTED_HEAD = 'f3f84ce6ba44f5391a5bec78418a5d78052a1b3d'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def snapshot(validate=False):
    manifest_path = PACKAGE / 'package-hashes.json'
    manifest = json.loads(manifest_path.read_text())
    result = {'package/' + name: sha(PACKAGE / name) for name in manifest['files']}
    result['package-manifest'] = sha(manifest_path)
    if validate and (result['package-manifest'] != EXPECTED_MANIFEST or
            any(result['package/' + name] != value for name, value in manifest['files'].items())):
        raise ValueError('reviewed paired package hash mismatch')
    for relative in ('solana-rpc-harness/driver.py', 'linux-harness/runtime_paths.py',
            'linux-harness/swap_journal.py', 'linux-harness/xds_localnet.py',
            'linux-harness/test_xds_wallet_network.py'):
        result[relative] = sha(STAGE / relative)
    result['runner'] = sha(pathlib.Path(__file__))
    result['sbf-file'] = sha(pathlib.Path('/opt/discrete-swap-lab/program-v3/solana_escrow.so'))
    result['validator-binary'] = sha(pathlib.Path('/opt/discrete-swap-lab/releases/solana-release/bin/solana-test-validator'))
    result['native-build-receipt'] = sha(NATIVE / 'run-manifests/linux-timer-build.json')
    sys.path.insert(0, str(NATIVE))
    try:
        from run_evidence import snapshot as native_snapshot
        result['native'] = native_snapshot()
    finally:
        sys.path.pop(0)
    if validate:
        built = json.loads((NATIVE / 'run-manifests/linux-timer-build.json').read_text())
        if (built['exit_code'] != 0 or not built['source_unchanged'] or
                built['after']['head'] != EXPECTED_HEAD or result['native'] != built['after']):
            raise ValueError('paired native artifacts differ from successful candidate build')
    return result


def sample():
    result = {'utc': now(), 'monotonic': time.monotonic(), 'cgroup': str(CGROUP)}
    for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'memory.events', 'memory.pressure', 'cpu.stat'):
        path = CGROUP / name
        result[name] = path.read_text().strip() if path.exists() else None
    return result


def oom_kills(entry):
    counters = dict(line.split() for line in entry['memory.events'].splitlines())
    return int(counters['oom_kill'])


def qualified(report, genesis):
    public = report.get('public_run', {})
    if (report['exit_code'] != 0 or not report['unchanged'] or public.get('status') != 'PASS' or
            public.get('genesis') != genesis or public.get('commitment') != 'finalized'):
        return False
    if any(name in report for name in ('runner_deadline_exceeded', 'runner_error_type',
            'evidence_error_type', 'public_report_error_type')):
        return False
    cases = public.get('cases', [])
    if [case.get('case') for case in cases] != ['success', 'abandonment'] or any(case.get('status') != 'PASS' for case in cases):
        return False
    if [case.get('coordinator_exposed') for case in cases] != [True, False]:
        return False
    samples = report['samples']
    return len(samples) >= 2 and oom_kills(samples[-1]) == oom_kills(samples[0])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-genesis', required=True)
    parser.add_argument('--label', choices=('paired-rpc-v3-run01', 'paired-rpc-v3-run02'), required=True)
    args = parser.parse_args()
    run = BASE / args.label
    report_path, log_path = BASE / (args.label + '-receipt.json'), BASE / (args.label + '.log')
    if run.exists() or report_path.exists() or log_path.exists():
        raise ValueError('immutable evidence name already exists')
    before = snapshot(validate=True)
    if not (CGROUP / 'memory.current').is_file():
        raise ValueError('expected live Solana resource cgroup absent')
    env = os.environ.copy()
    env.update(SWAP_CORE_DIR=str(NATIVE / 'core'), SWAP_BUILD_DIR=str(NATIVE / 'b'),
               XDS_DAEMON=str(NATIVE / 'b/src/discreted'), XDS_WALLET=str(NATIVE / 'b/src/simplewallet'))
    command = [sys.executable, '-B', '-u', str(PACKAGE / 'runner.py'), '--endpoint', 'http://127.0.0.1:8899',
               '--expected-genesis', args.expected_genesis, '--payer-keypair', str(BASE / 'payer.json'), '--run-dir', str(run)]
    report = {'schema': 1, 'started_utc': now(), 'command': command, 'before': before, 'samples': [],
              'python': sys.version, 'solders': importlib.metadata.version('solders'), 'status': 'INCOMPLETE'}
    started, process = time.monotonic(), None
    try:
        # Establish OOM counters before any runner or descendant can allocate.
        report['samples'].append(sample())
        with log_path.open('xb') as log:
            process = subprocess.Popen(command, cwd=PACKAGE, env=env, stdout=log, stderr=subprocess.STDOUT)
            while True:
                report['samples'].append(sample())
                if time.monotonic() - started > 1800:
                    report['runner_deadline_exceeded'] = True
                    break
                if process.poll() is not None:
                    break
                time.sleep(5)
    except Exception as error:
        report['runner_error_type'] = type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=15)
    report.update(ended_utc=now(), exit_code=process.returncode if process is not None else None)
    try:
        report.update(after=snapshot(), log_sha256=sha(log_path))
        report['samples'].append(sample())
    except Exception as error:
        report['evidence_error_type'] = type(error).__name__
    report['unchanged'] = report['before'] == report.get('after')
    try:
        public = run / 'run.json'
        if public.exists():
            report['public_run'] = json.loads(public.read_text())
            report['public_run_sha256'] = sha(public)
    except Exception as error:
        report['public_report_error_type'] = type(error).__name__
    try:
        passed = qualified(report, args.expected_genesis)
    except Exception as error:
        report['qualification_error_type'] = type(error).__name__
        passed = False
    report['status'] = 'PASS' if passed else 'FAIL'
    with report_path.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps({'status': report['status'], 'exit_code': report['exit_code'], 'unchanged': report['unchanged'],
                      'receipt': str(report_path), 'sha256': sha(report_path)}), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

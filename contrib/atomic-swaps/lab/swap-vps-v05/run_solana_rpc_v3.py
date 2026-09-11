"""Run the reviewed synthetic RPC suite with immutable public evidence and resource samples."""
import argparse, datetime, hashlib, importlib.metadata, json, os, pathlib, subprocess, sys, time

BASE = pathlib.Path('/var/lib/discrete-swap-lab')
PACKAGE = BASE / 'rpc-v3-stage/solana-rpc-harness'
CGROUP = pathlib.Path('/sys/fs/cgroup/discrete.slice/discrete-swap.slice/discrete-swap-solana.slice')
EXPECTED_DRIVER = '1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def snapshot(validate=False):
    manifest = json.loads((PACKAGE / 'package-hashes.json').read_text())
    result = {name: sha(PACKAGE / name) for name in manifest['files']}
    if validate and (result != manifest['files'] or result['driver.py'] != EXPECTED_DRIVER):
        raise ValueError('reviewed package hash mismatch')
    result['package-hashes.json'] = sha(PACKAGE / 'package-hashes.json')
    result['runner'] = sha(pathlib.Path(__file__))
    result['validator_binary'] = sha(pathlib.Path('/opt/discrete-swap-lab/releases/solana-release/bin/solana-test-validator'))
    result['sbf_file'] = sha(pathlib.Path('/opt/discrete-swap-lab/program-v3/solana_escrow.so'))
    return result


def sample():
    result = {'utc': now(), 'monotonic': time.monotonic(), 'cgroup': str(CGROUP)}
    for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'memory.events', 'memory.pressure', 'cpu.stat'):
        path = CGROUP / name
        result[name] = path.read_text().strip() if path.exists() else None
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-genesis', required=True)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if not args.label.replace('-', '').isalnum():
        raise ValueError('invalid label')
    run = BASE / args.label
    run.mkdir(mode=0o700, exist_ok=False)
    report_path = BASE / (args.label + '-receipt.json')
    log_path = BASE / (args.label + '.log')
    if report_path.exists() or log_path.exists():
        raise ValueError('immutable evidence name already exists')
    before = snapshot(validate=True)
    if not (CGROUP / 'memory.current').is_file():
        raise ValueError('expected live Solana resource cgroup absent')
    command = [sys.executable, '-B', '-u', str(PACKAGE / 'driver.py'), '--endpoint', 'http://127.0.0.1:8899',
               '--expected-genesis', args.expected_genesis, '--payer-keypair', str(BASE / 'payer.json'),
               '--run-dir', str(run), '--commitment', 'finalized']
    report = {'schema': 1, 'started_utc': now(), 'command': command, 'before': before, 'samples': [],
              'python': sys.version, 'solders': importlib.metadata.version('solders'), 'status': 'INCOMPLETE'}
    started, process = time.monotonic(), None
    try:
        with log_path.open('xb') as log:
            process = subprocess.Popen(command, cwd=PACKAGE, stdout=log, stderr=subprocess.STDOUT)
            while True:
                report['samples'].append(sample())
                if time.monotonic() - started > 900:
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
    except Exception as error:
        report['evidence_error_type'] = type(error).__name__
    report['unchanged'] = report['before'] == report.get('after')
    public = run / 'run.json'
    try:
        if public.exists():
            report['public_run'] = json.loads(public.read_text())
            report['public_run_sha256'] = sha(public)
    except Exception as error:
        report['public_report_error_type'] = type(error).__name__
    qualified = report.get('public_run', {})
    passed = report['exit_code'] == 0 and report['unchanged'] and qualified.get('status') == 'PASS'
    passed = passed and not any(name in report for name in ('runner_deadline_exceeded', 'runner_error_type', 'evidence_error_type', 'public_report_error_type'))
    passed = passed and qualified.get('commitment') == 'finalized' and len(qualified.get('cases', [])) == 6
    passed = passed and all(case.get('status') == 'PASS' for case in qualified.get('cases', []))
    passed = passed and qualified.get('genesis') == args.expected_genesis
    passed = passed and [case.get('name') for case in qualified.get('cases', [])] == [
        '01-fund', '02-wrong-secret-rejection', '03-claim-and-identical-duplicate',
        '04-next-transfer-after-claim', '05-early-refund-rejection', '06-refund-and-next-transfer']
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

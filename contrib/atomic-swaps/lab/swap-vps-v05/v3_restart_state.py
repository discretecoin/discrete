"""Owned private-ledger clean restart: preserve settled escrow and token state."""
import base64
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import time

LAB = pathlib.Path('/var/lib/discrete-swap-lab')
sys.path.insert(0, str(LAB / 'rpc-v3-stage/solana-rpc-harness'))
import driver as d

UNITS = [
    'discrete-swap-solana.target',
    'discrete-swap-solana-validator.service',
    'discrete-swap-solana-rpc.socket', 'discrete-swap-solana-rpc.service',
    'discrete-swap-solana-ws.socket', 'discrete-swap-solana-ws.service',
    'discrete-swap-escrow-v3.service', 'discrete-swap-paired-v3.service',
]
REPORT = LAB / 'v3-settled-state-restart-public.json'
VALIDATOR_SHA = 'd723f3a99fa3f5b3df6841fc04ac0d8b5302837689d43a07222aa2125b6713d1'
DRIVER_SHA = '1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def ctl(*args, deadline=None):
    timeout = 50 if deadline is None else deadline - time.monotonic()
    check(timeout > 0, 'systemd operation exceeded deadline before invocation')
    result = subprocess.check_output(['systemctl', *args], text=True, timeout=timeout).strip()
    check(deadline is None or time.monotonic() <= deadline, 'systemd operation exceeded deadline after return')
    return result


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_receipt(receipt, label, genesis):
    expected = (['01-fund', '02-wrong-secret-rejection', '03-claim-and-identical-duplicate',
                 '04-next-transfer-after-claim', '05-early-refund-rejection', '06-refund-and-next-transfer']
                if label.startswith('escrow-') else ['success', 'abandonment'])
    check(receipt['status'] == 'PASS' and receipt['exit_code'] == 0 and receipt['unchanged'], 'successful exact run required')
    public = receipt['public_run']
    check(public['status'] == 'PASS' and public['genesis'] == genesis and public['commitment'] == 'finalized', 'prior run identity/commitment mismatch')
    profile = public['profile']
    check(profile['program'] == str(d.PID) and profile['payload_sha256'] == d.SBF_SHA and
          profile['payload_bytes'] == d.SBF_SIZE and profile['version']['solana-core'] == '4.2.2', 'prior run program profile mismatch')
    check([case.get('name', case.get('case')) for case in public['cases']] == expected and
          all(case['status'] == 'PASS' for case in public['cases']), 'prior case identity/status mismatch')
    if label.startswith('paired-'):
        check([case['coordinator_exposed'] for case in public['cases']] == [True, False], 'paired exposure outcomes differ')


def stopped_state(deadline):
    result = {}
    for unit in UNITS:
        values = dict(line.split('=', 1) for line in ctl('show', unit, '-p', 'ActiveState', '-p', 'SubState',
                                                       '-p', 'MainPID', '-p', 'ControlGroup', deadline=deadline).splitlines())
        result[unit] = values
    return result


def stop_owned_target():
    deadline = time.monotonic() + 50
    ctl('stop', UNITS[0], deadline=deadline)
    while True:
        states = stopped_state(deadline)
        if all(row['ActiveState'] == 'inactive' and row.get('MainPID', '0') == '0' and not row.get('ControlGroup')
               for row in states.values()):
            return states
        check(time.monotonic() < deadline, 'target did not fully stop within bound')
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def snapshot(rpc):
    rpc.guard()
    profile = d.verify_program(rpc)
    states = rpc.call('getProgramAccounts', [str(d.PID), {'encoding': 'base64', 'commitment': 'finalized'}])
    check(len(states) == 4, 'expected exactly four owned settled escrow states')
    raw_states = [d.account_bytes(row['account']) for row in states]
    check(all(len(raw) == 192 for raw in raw_states), 'escrow state size')
    check(sorted(raw[8] for raw in raw_states) == [2, 2, 3, 3], 'expected two claims and two refunds')
    tokens = rpc.call('getProgramAccounts', [str(d.TOKEN), {
        'encoding': 'base64', 'commitment': 'finalized',
        'filters': [{'dataSize': 165}, {'memcmp': {'offset': 0, 'bytes': str(d.MINT)}}],
    }])
    check(len(tokens) == 16, 'expected sixteen token accounts for four owned fixtures')
    rows = states + tokens
    program = rpc.account(d.PID)
    programdata = d.Pubkey.from_bytes(d.account_bytes(program)[4:36])
    for key, account in [(d.PID, program), (programdata, rpc.account(programdata)), (d.MINT, rpc.account(d.MINT))]:
        rows.append({'pubkey': str(key), 'account': account})
    accounts = {}
    for row in rows:
        account = row['account']
        data = d.account_bytes(account)
        accounts[row['pubkey']] = {
            'lamports': account['lamports'], 'owner': account['owner'], 'executable': account['executable'],
            'data_bytes': len(data), 'data_sha256': hashlib.sha256(data).hexdigest(),
        }
    check(len(accounts) == 23, 'expected twenty-three unique public accounts')
    rpc.guard()
    return {'genesis': rpc.genesis, 'profile': profile, 'accounts': accounts, 'finalized_slot': rpc.slot()}


def main():
    check(not REPORT.exists(), 'immutable receipt name already exists')
    driver_sha = hashlib.sha256(pathlib.Path(d.__file__).read_bytes()).hexdigest()
    check(driver_sha == DRIVER_SHA, 'loaded driver source differs')
    prior = json.loads((LAB / 'v3-pre-upgrade-public.json').read_text())
    before_stop = {}
    for label, count in [('escrow-rpc-v3-run01', 6), ('paired-rpc-v3-run01', 2)]:
        path = LAB / (label + '-receipt.json')
        receipt = json.loads(path.read_text())
        validate_receipt(receipt, label, prior['genesis'])
        before_stop[label] = hashlib.sha256(path.read_bytes()).hexdigest()
    for unit in UNITS[-2:]:
        check(ctl('show', unit, '-p', 'ActiveState', '--value') == 'inactive', 'qualification runner must be stopped')
    rpc = d.Rpc('http://127.0.0.1:8899', prior['genesis'], 'finalized')
    report = {'status': 'INCOMPLETE', 'started_utc': now(), 'scope': 'clean validator/target restart after settled synthetic cases; not VPS reboot or power-loss recovery',
              'script_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
              'driver_sha256': driver_sha, 'run_receipts': before_stop}
    report['before'] = snapshot(rpc)
    report['old_pid'] = int(ctl('show', UNITS[1], '-p', 'MainPID', '--value'))
    check(report['old_pid'] > 0, 'validator not running')
    report['old_validator_sha256'] = hashlib.sha256(pathlib.Path('/proc', str(report['old_pid']), 'exe').read_bytes()).hexdigest()
    check(report['old_validator_sha256'] == VALIDATOR_SHA, 'old validator executable differs')
    try:
        report['stopped_units'] = stop_owned_target()
        report['old_pid_absent'] = not pathlib.Path('/proc', str(report['old_pid'])).exists()
        check(report['old_pid_absent'], 'old validator process remains')
        deadline = time.monotonic() + 90
        ctl('start', UNITS[0], deadline=deadline)
        while True:
            try:
                rpc.timeout = min(5, max(0.001, deadline - time.monotonic()))
                rpc.guard()
                check(time.monotonic() <= deadline, 'RPC genesis response exceeded deadline')
                rpc.timeout = min(5, max(0.001, deadline - time.monotonic()))
                slot = rpc.slot()
                check(time.monotonic() <= deadline, 'RPC slot response exceeded deadline')
                if slot >= report['before']['finalized_slot']:
                    break
            except (OSError, d.GateError, d.RpcError):
                pass
            check(time.monotonic() < deadline, 'restart RPC/finalized slot did not recover within bound')
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        rpc.timeout = 5
        report['new_pid'] = int(ctl('show', UNITS[1], '-p', 'MainPID', '--value'))
        check(report['new_pid'] > 0 and report['new_pid'] != report['old_pid'], 'validator PID must change')
        report['new_validator_sha256'] = hashlib.sha256(pathlib.Path('/proc', str(report['new_pid']), 'exe').read_bytes()).hexdigest()
        check(report['new_validator_sha256'] == VALIDATOR_SHA, 'validator executable differs')
        report['after'] = snapshot(rpc)
        check(all(report['before'][name] == report['after'][name] for name in ['genesis', 'profile', 'accounts']), 'settled account/profile state changed')
        report['status'] = 'PASS'
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['error'] = str(error)
        report['status'] = 'FAIL'
    finally:
        try:
            report['final_stopped_units'] = stop_owned_target()
            report['final_cleanup'] = 'PASS'
        except Exception as error:
            report['status'] = 'FAIL'
            report['final_cleanup'] = 'FAIL'
            report['cleanup_error_type'] = type(error).__name__
            report['cleanup_error'] = str(error)
        report['ended_utc'] = now()
        with REPORT.open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
        REPORT.chmod(0o644)
    print(json.dumps({'status': report['status'], 'receipt': str(REPORT), 'sha256': hashlib.sha256(REPORT.read_bytes()).hexdigest()}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

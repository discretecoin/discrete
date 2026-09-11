"""Execute a bounded local command with before/after source and binary manifests."""
import concurrent.futures,datetime,hashlib,json,pathlib,subprocess,sys
from runtime_paths import CORE,PATHS,artifact_key,executable_inventory
ROOT=pathlib.Path(__file__).resolve().parent
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def snapshot():
    git=['git','-c','safe.directory='+CORE.as_posix(),'-C',str(CORE)]
    head=subprocess.check_output(git+['rev-parse','HEAD'],text=True).strip()
    files=subprocess.check_output(git+['ls-files','-z','--cached','--others','--exclude-standard']).decode().split('\0')
    paths=[CORE/p for p in files if p and (CORE/p).is_file()]
    paths+=list(ROOT.glob('*.py'))+list(ROOT.glob('*.c'))+list(ROOT.glob('*.h'))+list(ROOT.glob('*.cmd'))
    paths+=list((ROOT/'scripts').rglob('*.py'))+list((ROOT/'scripts').rglob('*.cmd'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        hashes=dict(zip([artifact_key(p) for p in paths],pool.map(sha,paths)))
    binaries={artifact_key(p):sha(p) for p in executable_inventory() if p.is_file()}
    return {'head':head,'sources':hashes,'binaries':binaries,'runtime_paths':{k:str(v) for k,v in PATHS.items()}}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
if __name__=='__main__':
    name=sys.argv[1];command=sys.argv[2:];building=bool(command and command[0]=='--build')
    if building:command=command[1:]
    if not name.replace('-','').isalnum() or not command:raise ValueError('name and exact command required')
    folder=ROOT/'run-manifests';folder.mkdir(exist_ok=True)
    log=ROOT/(name+'.log');dest=folder/(name+'.json')
    if log.exists() or dest.exists():raise FileExistsError('immutable run name already exists')
    before=snapshot();started=now()
    with log.open('wb') as output:
        process=subprocess.run(command,cwd=ROOT,stdout=output,stderr=subprocess.STDOUT)
    ended=now();after=snapshot()
    report={'name':name,'command':command,'started_utc':started,'ended_utc':ended,
      'exit_code':process.returncode,'before':before,'after':after,'unchanged':before==after,
      'source_unchanged':before['sources']==after['sources'] and before['head']==after['head'],
      'binary_change_expected':building,
      'log':log.name,'log_sha256':sha(log)}
    dest.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'run':name,'exit_code':process.returncode,'unchanged':before==after,'log':str(log)}),flush=True)
    stable=report['source_unchanged'] if building else report['unchanged']
    raise SystemExit(process.returncode or (0 if stable else 97))

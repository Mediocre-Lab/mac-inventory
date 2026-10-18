#!/usr/bin/python3
"""Metadata-only inventory. Never imports or executes inventoried software."""
import datetime, json, os, plistlib, shlex, sys, stat, time, email.parser, configparser, hashlib
from pathlib import Path

HOME = Path.home()
items, warnings, coverage = [], [], []
seen = {}
metrics = dict(directories=0, files=0, aliases=0, denied=0, skipped=0)
last_progress = 0.0
def directory_progress(event, args):
 # Report metadata-phase directory opens, including os.walk/glob, before they
 # can wait on filesystem or macOS privacy access. Deep traversal has totals.
 if event in ('os.listdir','os.scandir') and metrics['directories']==0:
  print(json.dumps(dict(progress='Checking directory: '+str(args[0]))),file=sys.stderr,flush=True)
sys.addaudithook(directory_progress)
PURPOSE = {
 'Amphetamine':'Keep the Mac awake', 'ChatGPT':'AI assistant', 'Claude':'AI assistant',
 'Discord':'Community chat', 'Docker':'Containers and development services',
 'Firefox':'Web browser', 'Google Chrome':'Web browser', 'Safari':'Web browser',
 'Obsidian':'Markdown notes and knowledge base', 'Tailscale':'Private network access',
 'Visual Studio Code':'Code editor', 'Wispr Flow':'Voice dictation', 'Xcode':'Apple development tools',
 'iTerm':'Terminal', 'LibreOffice':'Documents, spreadsheets and presentations',
 'Hermes':'AI agent desktop interface', 'GridCraft':'Local custom app; purpose not verified',
 'WordCraft':'Local custom app; purpose not verified',
 'gh':'GitHub CLI', 'ffmpeg':'Audio and video conversion', 'poppler':'PDF utilities',
 'ripgrep':'Fast file text search', 'ollama':'Run local language models',
 'openai-whisper':'Speech transcription', 'redis':'In-memory database',
 'postgresql@17':'PostgreSQL database', 'peekaboo':'macOS UI automation',
 'cliclick':'Mouse and keyboard automation', 'gogcli':'Google services CLI',
 'goplaces':'Google Places CLI', 'spogo':'Spotify CLI', 'gifgrep':'GIF search CLI',
 'obsidian-cli':'Obsidian vault CLI', 'swiftlint':'Swift linting', 'swiftformat':'Swift formatting',
 'xcodegen':'Generate Xcode projects', 'xcodes':'Manage Xcode versions',
 'openclaw':'AI agent platform', 'clawhub':'OpenClaw skill registry CLI',
 'node-llama-cpp':'Local llama.cpp models for Node', '@openai/codex':'Codex coding CLI',
 '@playwright/mcp':'Browser automation MCP server', '@mermaid-js/mermaid-cli':'Render Mermaid diagrams',
 '@stepandel/agentmail-cli':'AgentMail CLI', 'corepack':'Node package-manager shims',
 'npm':'Node package manager', 'rea-agents':'Reverse engineering CLI and MCP server',
 'node@22':'Node.js JavaScript runtime', 'python@3.12':'Python runtime',
 'python@3.14':'Python runtime (Homebrew dependency)', 'tailscale':'Private network CLI',
 'libass':'Subtitle rendering library; explicitly installed',
 'nano-pdf':'Natural-language PDF editing CLI', 'hermes-agent':'Hermes AI agent CLI',
}

def add(name, version, kind, source, path, purpose='', launch='', status='Metadata present'):
 name=str(name)[:1000]
 # Real targets deduplicate symlink aliases; different installed copies remain distinct.
 canonical=os.path.realpath(str(path))
 key=(canonical, 'executable' if kind in ('Executable candidate','Apple tool') else name.casefold())
 if key in seen:
  item=seen[key]
  if str(path)!=item['location'] and str(path) not in item['aliases']:
   item['aliases'].append(str(path)); metrics['aliases']+=1
  return
 try:
  p=Path(path);s=p.lstat();t=p.stat()
  values=[s.st_dev,s.st_ino,s.st_mode,s.st_ctime_ns,str(p.resolve()),t.st_dev,t.st_ino,t.st_ctime_ns]
  fingerprint=hashlib.sha256(json.dumps(values,separators=(',',':')).encode()).hexdigest()
 except OSError:fingerprint=None
 item=dict(id=canonical+'|'+key[1], name=name, version=str(version or 'Unknown'),scanIdentity=fingerprint,
  kind=kind, source=source, location=str(path), purpose=purpose or PURPOSE.get(name,'Purpose not verified'),
  launch=launch, status=status, aliases=[])
 items.append(item);seen[key]=item

def read_metadata(p, limit=2_000_000):
 """Read a bounded regular file; reject final links and FIFO substitutions atomically."""
 fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode):raise ValueError('Non-regular metadata')
  if info.st_size>limit:raise ValueError('Oversized metadata')
  chunks=[];remaining=limit+1
  while remaining:
   chunk=os.read(fd,min(65536,remaining))
   if not chunk:break
   chunks.append(chunk);remaining-=len(chunk)
  data=b''.join(chunks)
  if len(data)>limit:raise ValueError('Oversized metadata')
  return data
 finally:os.close(fd)

def metadata_text(p, limit=2_000_000):
 return read_metadata(p,limit).decode('utf-8',errors='replace')

def read_json(p):
 try:
  data=json.loads(read_metadata(p))
  if not isinstance(data,dict):
   warnings.append('Non-object metadata skipped: '+str(p));return {}
  return data
 except Exception as e:
  warnings.append('Unreadable metadata: '+str(p)+' ('+type(e).__name__+': '+str(e)+')'); return {}

def children(p):
 try: return sorted(p.iterdir())
 except FileNotFoundError: return []
 except OSError as e:
  warnings.append('Cannot inspect '+str(p)+' ('+type(e).__name__+')'); return []

def read_app_metadata(p):
 try:
  data=plistlib.loads(read_metadata(p/'Contents/Info.plist'))
  if not isinstance(data,dict): raise ValueError('plist must be an object')
  return data
 except Exception as e:
  warnings.append('App metadata unreadable: '+str(p)+' ('+type(e).__name__+')');return {}

def npm_commands(d,p):
 # Metadata is untrusted: npm permits only strings or string-valued bin maps.
 name=d.get('name')
 if not isinstance(name,str) or not name:
  if name is not None:warnings.append('Invalid npm package name: '+str(p))
  name=p.name
 b=d.get('bin',{})
 if isinstance(b,dict):
  commands=[key for key,value in b.items() if isinstance(value,str)]
  if len(commands)!=len(b):warnings.append('Invalid npm command metadata: '+str(p))
 elif isinstance(b,str):commands=[name.split('/')[-1]] if b else []
 else:
  commands=[]
  if b:warnings.append('Invalid npm command metadata: '+str(p))
 return name,commands

def applications():
 for root in [Path('/Applications'),HOME/'Applications',Path('/System/Applications')]:
  coverage.append(str(root)+' (app bundles, plus Utilities)')
  for p in children(root)+children(root/'Utilities'):
   if p.suffix!='.app': continue
   d=read_app_metadata(p)
   name=p.stem
   kind='Apple app' if str(root).startswith('/System') or name=='Safari' else 'App'
   status='App bundle present; launch not tested'
   if '.backup' in name: kind='Backup'; status='Backup app bundle; excluded from installed app count'
   add(name,d.get('CFBundleShortVersionString') or d.get('CFBundleVersion'),kind,'App bundle',p,
    launch='Open in Finder or Spotlight',status=status)

def homebrew(prefix):
 root=prefix/'Cellar'; coverage.append(str(root)+' (receipt classification)')
 for formula in children(root):
  if not formula.is_dir(): continue
  for v in children(formula):
   receipt=read_json(v/'INSTALL_RECEIPT.json')
   direct=receipt.get('installed_on_request')
   commands=[x.name for x in children(v/'bin') if x.is_file()]
   kind=('Runtime' if formula.name.startswith(('python@','node@')) else 'CLI / tool' if commands else 'Library') if direct is True else 'Dependency' if direct is False else 'Unclassified'
   launch='Terminal: '+', '.join(commands[:6]) if commands else 'No standalone command found'
   add(formula.name,v.name,kind,'Homebrew',v,launch=launch,
    status='Explicit install in receipt' if direct else 'Dependency per receipt' if direct is False else 'Receipt classification unavailable')
 for cask in children(prefix/'Caskroom'):
  versions=[v.name for v in children(cask) if v.is_dir() and v.name not in ('.metadata','latest')]
  add(cask.name,', '.join(versions),'Package record','Homebrew cask',cask,
   purpose='Package-manager record; may duplicate an app bundle',status='Receipt/folder present; not an independent app count')

def npm(root, source='Global npm'):
 coverage.append(str(root)+' (top-level packages only)')
 packages=[]
 for p in children(root):
  packages.extend(children(p) if p.name.startswith('@') else [p])
 for p in packages:
  if not (p/'package.json').is_file(): continue
  d=read_json(p/'package.json'); name,commands=npm_commands(d,p)
  add(name,d.get('version'),'CLI / tool' if commands else 'Library',source,p,
   launch='Terminal: '+', '.join(commands) if commands else 'Library; no command declared')

def python_env(env, source):
 cfg=env/'pyvenv.cfg'
 if not cfg.is_file() or cfg.is_symlink(): return
 version='Unknown'
 try:
  lines=metadata_text(cfg,65536).splitlines()
  for line in lines:
   if line.startswith('version'): version=line.split('=',1)[-1].strip(); break
 except (OSError,ValueError) as e:
  warnings.append('Unreadable metadata: '+str(cfg)+' ('+type(e).__name__+')');return
 add(env.name,version,'Environment',source,env,purpose='Isolated Python environment; not a standalone app',
  launch='Use this environment\'s bin/python',status='Environment folder present; health not tested')

def python_tool(env,name,command):
 for p in env.glob('lib/python*/site-packages/*.dist-info/METADATA'):
  if not p.parent.name.lower().startswith(name.replace('-','_')): continue
  fields={}
  try: lines=metadata_text(p,262144).splitlines()
  except (OSError,ValueError) as e:
   warnings.append('Unreadable metadata: '+str(p)+' ('+type(e).__name__+')');continue
  for line in lines:
   if line.startswith(('Name: ','Version: ')):
    k,v=line.split(': ',1);fields[k]=v
  add(fields.get('Name',name),fields.get('Version'),'CLI / tool','Python environment',p.parent,
   launch='Terminal: '+command,status='Installed package metadata and command wrapper present')

def projects():
 coverage.append('~/Documents and ~/Projects (at most 3 levels; excludes caches, dependencies, QuantDinger)')
 prune={'node_modules','.git','.venv','venv','Codex','_vaults','worktrees','providers','dist','build','.cache'}
 for root in [HOME/'Documents', HOME/'Projects', HOME/'openclaw-mission-control']:
  if not root.is_dir(): continue
  for folder,dirs,files in os.walk(root):
   p=Path(folder); depth=len(p.relative_to(root).parts)
   dirs[:]=[x for x in dirs if x not in prune and 'quantdinger' not in x.lower() and not x.startswith('.')]
   if depth>=3: dirs[:]=[]
   if 'quantdinger' in str(p).lower(): dirs[:]=[];continue
   markers=[]
   if (p/'.git').exists(): markers.append('Git checkout')
   for file in ['package.json','pyproject.toml','requirements.txt']:
    if file in files: markers.append(file)
   if markers:
    add(p.name,None,'Repository / project','Local project',p,
     purpose='Project folder; installation and runnable state not established',
     launch='Reveal folder and read its README',status=', '.join(markers)+'; not counted as installed software')
   for env in ['.venv','venv']: python_env(p/env,'Project-local Python')

def special():
 rea=HOME/'Documents/REA'
 p=rea/'node_modules/rea-agents/package.json'
 if p.is_file():
  d=read_json(p);add('rea-agents',d.get('version'),'CLI / tool','Project-local npm',p.parent,
   launch='Terminal: '+shlex.quote(str(rea/'node_modules/.bin/rea')),
   status='Installed local npm package; CLI execution not tested')
 providers=rea/'providers';coverage.append(str(providers)+' (Ghidra / Java metadata)')
 for p in children(providers):
  if p.name.startswith('ghidra_'):
   add('Ghidra',p.name.removeprefix('ghidra_').removesuffix('_PUBLIC') if sys.version_info>=(3,9) else p.name,
    'CLI / tool','REA provider',p,purpose='Binary disassembly and decompilation',
    launch='Terminal: '+shlex.quote(str(p/'ghidraRun')),status='Provider folder and launcher present; launch not tested')
  for release in [p/'release',p/'Contents/Home/release']:
   if release.is_file():
    try: lines=metadata_text(release,65536).splitlines()
    except (OSError,ValueError) as e:
     warnings.append('Unreadable metadata: '+str(release)+' ('+type(e).__name__+')');continue
    version=next((s.split('=',1)[1].strip('"') for s in lines if s.startswith('JAVA_VERSION=')),'Unknown')
    add('Java JDK',version,'Runtime','REA provider',release.parent,purpose='Java runtime and compiler',
     launch='Terminal: '+shlex.quote(str(release.parent/'bin/java')),status='Runtime release metadata present')
 for root in [Path('/Library/Java/JavaVirtualMachines'),HOME/'Library/Java/JavaVirtualMachines']:
  for p in children(root):
   release=p/'Contents/Home/release'
   if release.is_file(): add(p.name,None,'Runtime','Java installation',p,purpose='Java runtime',launch='Use Contents/Home/bin/java')
 for env,name,cmd in [(HOME/'.hermes/hermes-agent/venv','hermes-agent','hermes'),(HOME/'.local/share/uv/tools/nano-pdf','nano-pdf','nano-pdf')]:
  python_tool(env,name,cmd)
 for p in children(HOME/'.local/share/uv/python'):
  if p.name.startswith('cpython-') and not p.is_symlink():
   add('Python (uv)',p.name.split('-')[1],'Runtime','uv managed',p,purpose='Python runtime',launch='Use bin/python in this folder')
 for name in ['uv','uvx','claude','paperclip-ceo']:
  p=HOME/'.local/bin'/name
  if p.exists():
   ver=p.resolve().name if name=='claude' else None
   add(name,ver,'CLI / tool','User command',p,purpose={'uv':'Python package and environment manager','uvx':'Run Python tools in isolated environments','claude':'Claude Code CLI','paperclip-ceo':'Hermes paperclip-ceo profile launcher'}[name],launch='Terminal: '+name)

def progress(path, force=False):
 global last_progress
 now=time.monotonic()
 if force or now-last_progress>0.4:
  print(json.dumps(dict(progress=f"{metrics['directories']:,} folders · {metrics['files']:,} files · {len(items):,} records", path=str(path))),file=sys.stderr,flush=True)
  last_progress=now

def denied(error):
 metrics['denied']+=1
 warnings.append('Inaccessible: '+str(error.filename or 'unknown path')+' ('+type(error).__name__+')')

def app_bundle(p):
 d=read_app_metadata(p)
 name=p.stem
 kind='Apple app' if str(p).startswith('/System/') else 'App'
 if '.backup' in name: kind='Backup'
 add(name,d.get('CFBundleShortVersionString') or d.get('CFBundleVersion'),kind,'Discovered app bundle',p,
  launch='Open in Finder or Spotlight',status='App bundle present; launch not tested')

def python_distribution(p):
 metadata=p/'METADATA' if p.suffix=='.dist-info' else p/'PKG-INFO'
 if not metadata.is_file(): return
 try:
  headers=email.parser.Parser().parsestr(metadata_text(metadata,262144),headersonly=True)
 except (OSError,ValueError) as e:
  warnings.append('Unreadable metadata: '+str(metadata)+' ('+type(e).__name__+')');return
 name=headers.get('Name') or p.stem
 command_names=[]
 entry=p/'entry_points.txt'
 if entry.is_file():
  try:
   cfg=configparser.ConfigParser(interpolation=None);cfg.read_string(metadata_text(entry,262144))
   if cfg.has_section('console_scripts'):command_names=list(cfg['console_scripts'])
  except Exception: warnings.append('Entry-point metadata unreadable: '+str(entry))
 managed='site-packages' in str(p) or 'dist-packages' in str(p)
 tool_env='/uv/tools/' in str(p) or '/pipx/venvs/' in str(p)
 requested=(p/'REQUESTED').exists()
 kind='CLI / tool' if command_names and (tool_env or requested) else 'Library' if requested else 'Dependency' if managed else 'Unclassified'
 add(name,headers.get('Version'),kind,'Python installed distribution',p,
  launch='Declared console entry points: '+', '.join(command_names) if command_names else 'Python package; no console entry points declared',
  status='Explicit-install REQUESTED marker present' if requested else 'Installed distribution metadata; direct/transitive intent not established')

def recovery_capsule(p):
 prefix='.mac-inventory-removal-'
 if not p.name.startswith(prefix):return False
 suffix=p.name[len(prefix):]
 if len(suffix)!=32 or any(c not in '0123456789abcdef' for c in suffix):return False
 try:
  d=json.loads(read_metadata(p/'recovery.json',16384))
  info=p.lstat()
  if not isinstance(d,dict):raise ValueError('Invalid recovery marker')
  original=d.get('originalPath');root=d.get('confirmedRoot');capsule=d.get('capsule')
  if not isinstance(original,str) or len(original)>4096 or not Path(original).is_absolute() or '..' in Path(original).parts:raise ValueError('Invalid original path')
  if d.get('method') not in ('trash','permanent') or d.get('state')!='Captured or pending; contents may be partially deleted after interruption':raise ValueError('Invalid recovery state')
  if not isinstance(root,list) or len(root)!=3 or any(type(x)!=int for x in root):raise ValueError('Invalid root identity')
  if not isinstance(capsule,list) or len(capsule)!=3 or any(type(x)!=int for x in capsule) or capsule!=[info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)] or not stat.S_ISDIR(info.st_mode):raise ValueError('Recovery capsule identity mismatch')
  if root[2] not in (stat.S_IFDIR,stat.S_IFREG):raise ValueError('Invalid recovered object type')
 except Exception as e:
  warnings.append('Invalid recovery marker: '+str(p)+' ('+type(e).__name__+')');return False
 add(Path(original).name,None,'Remnant','Interrupted removal recovery',p,
  purpose='Recovery evidence from a manual removal; not an installed app or package',
  launch='Inspect recovery.json and target manually; no automatic recovery is performed',
  status='Potentially partial removal; original path: '+original+'; recovery capsule: '+str(p)+' (best-effort location)')
 warnings.append('Potentially partial removal recovery: '+str(p)+'; original path: '+original+'; inspect recovery.json and target manually (paths are best effort)')
 coverage.append('Recovery capsule contents excluded: '+str(p))
 return True

def deep_scan(roots):
 """Iterative depth-unbounded walk, no directory symlink following or binary execution."""
 visited=set()
 cache_names={'Caches','.cache','.npm','__pycache__','.Trash','.gradle','.m2','node-compile-cache','Cache','Code Cache','GPUCache'}
 excluded_names={'.git','.svn','.hg'}
 for root in roots:
  if not root.exists():
   coverage.append('Absent or unmounted: '+str(root));continue
  canonical=os.path.realpath(str(root))
  if canonical in visited: continue
  coverage.append('Deep traversal: '+str(root))
  stack=[root]
  while stack:
   p=stack.pop()
   canonical=os.path.realpath(str(p))
   if canonical in visited: continue
   if str(p).startswith('/System/Volumes'):
    metrics['skipped']+=1;coverage.append('OS volume internals excluded; data covered via visible roots: '+str(p));continue
   if 'quantdinger' in canonical.casefold():
    metrics['skipped']+=1;coverage.append('Excluded active task: '+str(p));continue
   visited.add(canonical);metrics['directories']+=1;progress(p)
   if recovery_capsule(p):metrics['skipped']+=1;continue
   if p.name.endswith(('.backupdb','.previous','.backup')) or p.name in ('Backups.backupdb','Backups'):
    add(p.name,None,'Backup','Filesystem',p,purpose='Historical backup directory; not a current installation',status='Directory recorded; historical copies intentionally excluded')
    metrics['skipped']+=1;coverage.append('Historical backup contents excluded: '+str(p));continue
   if p.name in cache_names:
    add(p.name,None,'Cache','Filesystem',p,purpose='Cache or trash directory; contents excluded from installed software',status='Directory recorded; contents intentionally skipped')
    metrics['skipped']+=1;continue
   if p.name in excluded_names: metrics['skipped']+=1;continue
   if p.suffix=='.app':
    app_bundle(p)
    # Nested helpers can be inventory-relevant, so enumerate bundles but not executable internals.
   if p.suffix in ('.dist-info','.egg-info'):
    python_distribution(p);continue
   try:
    entries=list(os.scandir(p))
   except OSError as e: denied(e);continue
   names={e.name for e in entries}
   if p.name=='conda-meta':
    for e in entries:
     if e.name.endswith('.json') and not e.is_symlink():
      d=read_json(Path(e.path))
      if d.get('name'):add(d['name'],d.get('version'),'Dependency','Conda environment',Path(e.path),purpose='Installed Conda environment package',status='Conda package metadata present')
   if 'release' in names and (p/'bin/java').is_file() and not (p/'release').is_symlink():
    try:
     lines=metadata_text(p/'release',65536).splitlines()
     version=next((line.split('=',1)[1].strip('"') for line in lines if line.startswith('JAVA_VERSION=')),None)
     if version:add('Java JDK',version,'Runtime','Discovered Java runtime',p,purpose='Java runtime and compiler',launch='Use bin/java in this folder',status='Java release metadata present; never executed')
    except (OSError,ValueError) as e:warnings.append('Unreadable metadata: '+str(p/'release')+' ('+type(e).__name__+')')
   if '.git' in names:
    add(p.name,None,'Repository / project','Git checkout',p,purpose='Repository folder; runnable state not established',launch='Reveal folder and read README',status='Git marker present; not assumed installed')
   if 'pyvenv.cfg' in names: python_env(p,'Discovered Python environment')
   if 'package.json' in names:
    d=read_json(p/'package.json')
    in_modules='node_modules' in p.parts
    name,commands=npm_commands(d,p)
    if in_modules:
     is_global='/lib/node_modules/' in str(p) and str(p).split('/lib/node_modules/',1)[1].count('/node_modules/')==0
     add(name,d.get('version'),'CLI / tool' if is_global and commands else 'Dependency','npm package',p,
      launch='Declared commands: '+', '.join(commands) if commands else 'Node package; no command declared',
      status='Installed node_modules package; transitive/direct project classification not established')
    elif '.git' not in names:
     add(name,d.get('version'),'Repository / project','Project manifest',p,
      purpose='Project manifest; installation not established',launch='Reveal folder and read README',status='package.json present outside node_modules')
   elif any(n in names for n in ('pyproject.toml','requirements.txt','Cargo.toml','go.mod')) and '.git' not in names:
    add(p.name,None,'Repository / project','Project manifest',p,purpose='Project folder; installation not established',launch='Reveal folder and read README')
   for e in entries:
    try:
     if e.is_symlink():
      # Only record symlink commands. Never traverse directory links (including loops).
      if e.is_file() and p.name in ('bin','sbin','.bin'):
       target=os.path.realpath(e.path)
       if 'quantdinger' not in target.casefold():
        add(e.name,None,'Executable candidate','Command symlink',Path(e.path),purpose='Command alias; identity and usability not verified',launch='Review target before running',status='Symlink target present; never executed')
      continue
     if e.is_dir(follow_symlinks=False): stack.append(Path(e.path));continue
     metrics['files']+=1
     st=e.stat(follow_symlinks=False)
     if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and Path(e.name).suffix.lower() not in ('.so','.dylib','.a','.o','.dll','.class'):
      # Ignore executable artifacts inside application bundles; those belong to their app.
      if not any(part.endswith('.app') for part in p.parts):
       kind='Apple tool' if str(p).startswith(('/usr/bin','/usr/sbin','/bin','/sbin','/System/')) else 'Executable candidate'
       add(e.name,None,kind,'Executable file',Path(e.path),purpose='Executable permission present; identity and usability not verified',launch='Review file before running',status='Filesystem executable bit; never executed')
    except OSError as error: denied(error)
  progress(root,True)

def classify_records():
 """Keep application helpers, archived bundle contents and packaged npm out of direct installs."""
 unreadable={w.split(': ',1)[1].rsplit(' (',1)[0] for w in warnings if w.startswith('App metadata unreadable: ')}
 for item in items:
  p=Path(item['location']);parents=p.parent.parts
  if any(part.endswith('.backup.app') for part in p.parts):
   item['kind']='Backup'
   if '; archived app bundle contents' not in item['status']:item['status']+='; archived app bundle contents'
  elif item['source'] in ('App bundle','Discovered app bundle') and str(p) in unreadable:
   item['kind']='Unclassified';item['status']='App-shaped directory; Info.plist could not be read, installation not established'
  elif item['kind'] in ('App','Apple app') and (any(part.endswith('.app') for part in parents) or any(part.endswith('.platform') for part in parents)):
   item['kind']='Bundled app';item['status']+='; helper or development-platform bundle, not a separate top-level app'
  elif item['kind']=='App' and any(part.casefold() in ('templates','samples','examples') for part in parents):
   item['kind']='Unclassified';item['status']+='; template/sample bundle, not established as an installed user app'
  if item['kind']=='CLI / tool' and item['source']=='npm package' and (any(part.endswith('.app') for part in parents) or '/.codex/' in str(p)):
   item['kind']='Dependency';item['status']+='; packaged tooling rather than a separate user CLI install'

def scan():
 applications()
 for prefix in [Path('/opt/homebrew'),Path('/usr/local')]:
  if (prefix/'Cellar').exists(): homebrew(prefix)
 roots=[Path('/opt/homebrew/lib/node_modules'),Path('/usr/local/lib/node_modules'),HOME/'.local/lib/node_modules',HOME/'.npm-global/lib/node_modules',HOME/'.hermes/node/lib/node_modules']
 roots+=list((HOME/'.nvm/versions/node').glob('*/lib/node_modules'))
 for root in roots:
  if root.is_dir(): npm(root, 'Hermes bundled npm' if '.hermes' in str(root) else 'Global npm')
 gcloud=Path('/opt/homebrew/bin/gcloud')
 if gcloud.exists():
  cask=Path('/opt/homebrew/Caskroom/gcloud-cli')
  versions=[p.name for p in children(cask) if p.name not in ('latest','.metadata')]
  add('Google Cloud CLI', ', '.join(versions),'CLI / tool','Homebrew cask',gcloud.resolve(),
   purpose='Manage Google Cloud services',launch='Terminal: gcloud',status='Command target present; login not tested')
 projects();special()
 roots=[Path('/Applications'),Path('/Users'),Path('/Library'),Path('/System'),Path('/opt'),Path('/usr/local'),Path('/usr/bin'),Path('/usr/sbin'),Path('/bin'),Path('/sbin')]
 for volume in children(Path('/Volumes')):
  if volume.is_symlink() or os.path.realpath(str(volume))=='/':
   coverage.append('Volume alias (already covered system paths): '+str(volume))
  elif volume.is_dir(): roots.append(volume)
 deep_scan(roots)
 classify_records()
 coverage.append(f"Traversal totals: {metrics['directories']:,} folders, {metrics['files']:,} files, {metrics['denied']:,} inaccessible entries, {len(warnings):,} total warnings, {metrics['skipped']:,} excluded directory roots, {metrics['aliases']:,} aliases merged")
 return dict(scannedAt=datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
  items=sorted(items,key=lambda x:(x['name'].casefold(),x['location'])),warnings=warnings,coverage=coverage,
  limitations=['Presence and metadata only: no launch, service, login or account validation.',
   'Project folders are not assumed installed. Full npm/Python dependency metadata and executable candidates have separate categories.',
   'QuantDinger paths, processes and browsers excluded. No configuration, credentials or histories read.',
   'No guaranteed complete inventory: permission-denied paths, unmounted disks, containers/images, remote installs and software lacking recognizable metadata can be missed.',
   'Deep traversal covers Applications, Users, Library, System (excluding OS volume internals), opt, usr/local, system command directories and mounted non-alias Volumes. Private OS data outside these roots is not crawled.',
   'Directory symlinks are not followed. Cache/trash contents, historical backup trees and version-control internals are summarized, not crawled. App executable internals are not separate tools.',
   'Version Unknown means metadata was unavailable. Command PATH selection may differ from these locations.',
   'App presence does not establish that its external launch targets exist.'])

if __name__=='__main__':
 try: print(json.dumps(scan(),ensure_ascii=False))
 except Exception as e:
  print(json.dumps({'error':'Scan failed ('+type(e).__name__+'). Try Refresh.'}));sys.exit(1)

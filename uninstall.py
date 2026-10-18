#!/usr/bin/python3
"""Deterministic removal planner. Planning is read-only. Execution needs the exact confirmed token."""
import csv, io, email.parser, hashlib, json, os, plistlib, re, shutil, signal, stat, subprocess, sys, threading, ctypes, errno, secrets, contextlib
from pathlib import Path

class Refused(Exception): pass

@contextlib.contextmanager
def mutation_section():
 """Keep cancellation from interrupting atomic mutation/state bookkeeping pairs."""
 previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM})
 try:yield
 finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)

def rename_exclusive(source_fd,source,destination_fd,destination):
 """macOS atomic, descriptor-relative rename with no replacement or copy fallback."""
 if sys.platform!='darwin':raise Refused('Safe manual removal requires macOS exclusive rename support')
 library=ctypes.CDLL(None,use_errno=True)
 operation=getattr(library,'renameatx_np',None)
 if operation is None:raise Refused('Safe exclusive rename is unavailable; nothing was removed')
 operation.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
 operation.restype=ctypes.c_int
 if operation(source_fd,os.fsencode(source),destination_fd,os.fsencode(destination),4):
  code=ctypes.get_errno();raise OSError(code,os.strerror(code),str(destination))

def object_key(info):return (info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode))

class AnchoredDirectories:
 """Retain each nofollow ancestor descriptor and detect detached directory links."""
 def __init__(self):self.descriptors=[];self.links=[]
 def open(self,path):
  path=Path(path)
  if not path.is_absolute() or '..' in path.parts:raise Refused('Manual path is not canonical and absolute')
  current=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.descriptors.append(current)
  for component in path.parts[1:]:
   following=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
   self.descriptors.append(following);self.links.append((current,component,object_key(os.fstat(following))))
   current=following
  self.validate();return current
 def validate(self):
  for parent,name,expected in self.links:
   if object_key(os.stat(name,dir_fd=parent,follow_symlinks=False))!=expected:
    raise Refused('An opened directory ancestor moved or changed; manual operation stopped')
 def close(self):
  for fd in reversed(self.descriptors):os.close(fd)

def manual_mutation(plan,method,home):
 """Capture the confirmed root before mutation; retain a recovery capsule on failure.

 Descriptor anchoring and parent-link checks constrain ordinary replacement races.
 They are not a transaction against another hostile process running as this same UID.
 """
 if method not in ('trash','permanent'):raise Refused('Unsupported manual removal method')
 target=Path(plan['target']);anchors=AnchoredDirectories();capsule_fd=None
 capsule_name=None;capsule_key=None;captured=False;partial=False;committed=False;trash_name=None
 parent_fd=None;previous=None;cancelled=False
 def cancellation(signum,frame):
  nonlocal cancelled
  cancelled=True
 def check_cancelled():
  if cancelled:raise Refused('Manual operation cancelled')
 def checked_parent():
  anchors.validate()
  if capsule_key is not None and object_key(os.stat(capsule_name,dir_fd=parent_fd,follow_symlinks=False))!=capsule_key:
   raise Refused('Recovery capsule moved or changed; manual operation stopped')
 def recovery():
  return str(target.parent/capsule_name/'target')+'; recovery.json is beside it (path is best effort if an ancestor moved; capsule device/inode '+str(capsule_key[:2])+')'
 def cleanup_capsule():
  checked_parent()
  os.unlink('recovery.json',dir_fd=capsule_fd)
  os.rmdir(capsule_name,dir_fd=parent_fd)
 def ensure_link(parent,name,key):
  checked_parent()
  if object_key(os.stat(name,dir_fd=parent,follow_symlinks=False))!=key:
   raise Refused('A captured directory link changed; manual operation stopped')
 def erase(parent,name,expected,device,chain):
  nonlocal partial
  check_cancelled()
  for ancestor_parent,ancestor_name,key in chain:ensure_link(ancestor_parent,ancestor_name,key)
  current=os.stat(name,dir_fd=parent,follow_symlinks=False)
  if object_key(current)!=expected or current.st_dev!=device:raise Refused('Captured contents changed identity or filesystem; manual operation stopped')
  if stat.S_ISDIR(current.st_mode):
   fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
   try:
    if object_key(os.fstat(fd))!=expected:raise Refused('Directory changed while opening; manual operation stopped')
    descendants=chain+[(parent,name,expected)]
    with os.scandir(fd) as entries:
     names=[entry.name for entry in entries]
    for leaf in names:
     info=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
     erase(fd,leaf,object_key(info),device,descendants)
    for ancestor_parent,ancestor_name,key in descendants:ensure_link(ancestor_parent,ancestor_name,key)
    with mutation_section():
     check_cancelled();os.rmdir(name,dir_fd=parent);partial=True
   finally:os.close(fd)
  else:
   for ancestor_parent,ancestor_name,key in chain:ensure_link(ancestor_parent,ancestor_name,key)
   checked_parent()
   with mutation_section():
    check_cancelled();os.unlink(name,dir_fd=parent);partial=True
 try:
  previous=signal.signal(signal.SIGTERM,cancellation)
  parent_fd=anchors.open(target.parent)
  expected_parent=plan['identities'][str(target.parent)]
  if object_key(os.fstat(parent_fd))!=(expected_parent[0],expected_parent[1],stat.S_IFMT(expected_parent[2])):
   raise Refused('Confirmed parent directory changed; nothing was removed')
  expected=plan['identities'][str(target)]
  current=os.stat(target.name,dir_fd=parent_fd,follow_symlinks=False)
  if [current.st_dev,current.st_ino,current.st_mode,current.st_size,current.st_mtime_ns,current.st_ctime_ns]!=expected[:6]:
   raise Refused('Target changed before capture; nothing was removed')
  if current.st_uid!=os.getuid() or stat.S_ISLNK(current.st_mode) or current.st_dev!=os.fstat(parent_fd).st_dev:
   raise Refused('Target owner, type or mounted filesystem is unsafe for manual removal')
  capsule_name='.mac-inventory-removal-'+secrets.token_hex(16)
  with mutation_section():
   os.mkdir(capsule_name,0o700,dir_fd=parent_fd)
   capsule_fd=os.open(capsule_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
   info=os.fstat(capsule_fd);capsule_key=object_key(info)
   if info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_dev!=current.st_dev:
    raise Refused('Private recovery capsule is unsafe')
   checked_parent()
   journal=dict(originalPath=str(target),method=method,confirmedRoot=list(object_key(current)),capsule=list(capsule_key),state='Captured or pending; contents may be partially deleted after interruption')
   journal_fd=os.open('recovery.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=capsule_fd)
   try:
    data=memoryview(json.dumps(journal,ensure_ascii=False).encode())
    while data:
     written=os.write(journal_fd,data)
     if written<=0:raise OSError('Recovery journal write did not progress')
     data=data[written:]
    os.fsync(journal_fd)
   finally:os.close(journal_fd)
   check_cancelled()
   rename_exclusive(parent_fd,target.name,capsule_fd,'target');captured=True
  # Rename changes ctime; pin the original root's device, inode and file type.
  actual=os.stat('target',dir_fd=capsule_fd,follow_symlinks=False)
  if object_key(actual)!=object_key(current):raise Refused('Target was replaced during capture; no captured contents were deleted')
  checked_parent();check_cancelled()
  if method=='trash':
   home_fd=anchors.open(home);expected_home=plan['identities'][str(home)]
   if object_key(os.fstat(home_fd))!=(expected_home[0],expected_home[1],stat.S_IFMT(expected_home[2])):
    raise Refused('Confirmed home directory changed; Trash was not modified')
   try:os.mkdir('.Trash',0o700,dir_fd=home_fd)
   except FileExistsError:pass
   trash_fd=os.open('.Trash',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=home_fd)
   try:
    trash_info=os.fstat(trash_fd);trash_key=object_key(trash_info)
    if trash_info.st_uid!=os.getuid() or trash_info.st_mode&0o077:raise Refused('Trash must be a private directory owned by the current user')
    if trash_info.st_dev!=actual.st_dev:raise Refused('Trash is on another filesystem; no cross-device copy or deletion is offered')
    for attempt in range(10):
     trash_name=target.name if attempt==0 else secrets.token_hex(12)+'-'+target.name.encode()[:160].decode(errors='ignore')
     checked_parent();check_cancelled()
     if object_key(os.stat('.Trash',dir_fd=home_fd,follow_symlinks=False))!=trash_key:raise Refused('Trash directory changed; operation stopped')
     try:
      with mutation_section():
       rename_exclusive(capsule_fd,'target',trash_fd,trash_name);captured=False;committed=True
      break
     except FileExistsError:continue
    if not committed:raise Refused('Trash destination collisions prevented a safe move')
   finally:os.close(trash_fd)
  else:
   erase(capsule_fd,'target',object_key(actual),actual.st_dev,[])
   with mutation_section():captured=False;committed=True
  cleanup_capsule()
  output=('Moved the confirmed target to '+str(Path(home)/'.Trash'/trash_name)+'. This direct Trash move has no Finder Put Back bookkeeping; restore it manually from Trash.' if method=='trash' else 'Confirmed target permanently deleted through descriptor-relative traversal. Related data and manager records were retained.')
  return dict(success=True,output=output,target=str(target))
 except Exception as error:
  if committed:
   return dict(success=True,output=('Confirmed move to '+str(Path(home)/'.Trash'/trash_name)+' completed before interruption. No Finder Put Back bookkeeping.' if method=='trash' else 'Confirmed target deletion completed before interruption.')+' Recovery metadata may remain at '+str(target.parent/capsule_name)+'.',target=str(target))
  if captured:
   if not partial:
    try:
     # Never overwrite an item created at the original location during the operation.
     with mutation_section():
      rename_exclusive(capsule_fd,'target',parent_fd,target.name);captured=False
    except Exception:
     raise Refused(str(error)+'; all captured data was preserved. Recovery: '+recovery()) from error
    try:cleanup_capsule()
    except Exception:
     raise Refused(str(error)+'; captured target was restored to its original entry in the pinned parent (best-effort path '+str(target)+'). Recovery metadata cleanup failed; residue may remain at '+str(target.parent/capsule_name)+'. Nothing was deleted.') from error
    raise Refused(str(error)+'; captured target restored to its original entry in the pinned parent without overwriting any item. Nothing was deleted.') from error
   raise Refused(str(error)+'; deletion may be partial and was not silently restored. Recovery: '+recovery()) from error
  if capsule_name is not None and capsule_fd is not None:
   try:cleanup_capsule()
   except Exception:
    raise Refused(str(error)+'; no target contents were deleted. Recovery metadata may remain at '+str(target.parent/capsule_name)) from error
  raise
 finally:
  if capsule_fd is not None:os.close(capsule_fd)
  anchors.close()
  if previous is not None:signal.signal(signal.SIGTERM,previous)

def selection_identity(path):
 s=path.lstat();t=path.stat()
 values=[s.st_dev,s.st_ino,s.st_mode,s.st_ctime_ns,str(path.resolve()),t.st_dev,t.st_ino,t.st_ctime_ns]
 return hashlib.sha256(json.dumps(values,separators=(',',':')).encode()).hexdigest()

def read_metadata(path,limit=4_000_000):
 """Bind reads to one bounded regular descriptor; links/FIFOs cannot block planning."""
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode):raise Refused('Ownership metadata is not a regular file: '+str(path))
  if info.st_size>limit:raise Refused('Ownership metadata exceeds verification size limit')
  chunks=[];remaining=limit+1
  while remaining:
   chunk=os.read(fd,min(65536,remaining))
   if not chunk:break
   chunks.append(chunk);remaining-=len(chunk)
  data=b''.join(chunks)
  if len(data)>limit:raise Refused('Ownership metadata exceeds verification size limit')
  return data
 finally:os.close(fd)

def metadata(path):
 if path.is_symlink() or path.stat().st_size > 4_000_000: raise Refused('Metadata is linked or too large to verify safely: '+str(path))
 obj=json.loads(read_metadata(path))
 if not isinstance(obj,dict): raise Refused('Invalid ownership metadata')
 return obj

def identity(path):
 """lstat plus canonical target identity; hashes ownership files, never discovered code."""
 s=path.lstat()
 out=[s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 if path.is_symlink():
  out += [os.readlink(path),str(path.resolve(strict=True))]
  t=path.stat();out += [t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns]
 elif path.is_file() and path.name in ('package.json','package-lock.json','.package-lock.json','npm-shrinkwrap.json','INSTALL_RECEIPT.json','INSTALLER','METADATA','RECORD','REQUESTED','uv-receipt.toml','pyvenv.cfg','Info.plist'):
  if s.st_size>4_000_000: raise Refused('Ownership metadata exceeds verification size limit')
  out.append(hashlib.sha256(read_metadata(path)).hexdigest())
 return out

def valid_name(name,npm=False):
 pattern=r'(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*' if npm else r'[a-z0-9][a-z0-9@+._-]*'
 if not isinstance(name,str) or not re.fullmatch(pattern,name):raise Refused('Package identifier is invalid or ambiguous')
 return name

def normalized(name):return re.sub(r'[-_.]+','-',name).lower()

def package_headers(path):
 if path.is_symlink() or path.stat().st_size>4_000_000:raise Refused('Installed package metadata is linked or too large to verify')
 return email.parser.Parser().parsestr(read_metadata(path).decode(errors='replace'),headersonly=True)

class Planner:
 def __init__(self,home=None,brew_prefixes=None,npm_managers=None):
  self.home=Path(home or Path.home())
  self.brews=[Path(p) for p in (brew_prefixes if brew_prefixes is not None else ['/opt/homebrew','/usr/local'])]
  self.npm_managers=npm_managers if npm_managers is not None else [(p/'bin/node',p/'lib/node_modules/npm/bin/npm-cli.js') for p in self.brews]

 def blocked(self,why):raise Refused(why)

 def npm_metadata(self,path,proof):
  """Read Homebrew's linked Node manifests only after verifying the exact owning keg."""
  absolute=Path(os.path.abspath(path));resolved=path.resolve(strict=True)
  proof.append(path)
  if resolved==absolute:return metadata(path)
  for prefix in self.brews:
   try:
    logical=absolute.relative_to(prefix/'lib/node_modules')
    physical=resolved.relative_to(prefix/'Cellar')
   except ValueError:continue
   if logical.name!='package.json' or len(physical.parts)<6 or physical.parts[2:4]!=('lib','node_modules') or physical.name!='package.json':continue
   expected=logical.parent.as_posix();actual=Path(*physical.parts[4:-1]).as_posix()
   if expected!=actual or not (physical.parts[0]=='node' or physical.parts[0].startswith('node@')):continue
   receipt=prefix/'Cellar'/physical.parts[0]/physical.parts[1]/'INSTALL_RECEIPT.json'
   owner=metadata(receipt)
   if not isinstance(owner.get('installed_on_request'),bool):raise Refused('Linked npm metadata has no verified Homebrew Node receipt')
   data=metadata(resolved)
   if data.get('name')!=expected:raise Refused('Linked npm metadata does not match its registered package identity')
   proof.extend([resolved,receipt]);return data
  raise Refused('Linked npm metadata resolves outside its verified Homebrew Node ownership boundary: '+str(path))

 def reverse_brew(self,prefix,name):
  refs=[];files=list((prefix/'Cellar').glob('*/*/INSTALL_RECEIPT.json'))+list((prefix/'Caskroom').glob('*/.metadata/INSTALL_RECEIPT.json'))
  for file in files:
   d=metadata(file);deps=d.get('runtime_dependencies',[])
   if isinstance(deps,dict):deps=[x for values in deps.values() if isinstance(values,list) for x in values]
   if not isinstance(deps,list):raise Refused('Cannot establish reverse dependencies from an installed receipt')
   if any(isinstance(x,dict) and x.get('full_name','').split('/')[-1]==name for x in deps):refs.append(str(file))
  if refs:raise Refused('Shared dependency: installed packages require this target. No removal offered.\n'+'\n'.join(refs[:15]))
  return files

 def finish(self,item,target,manager,argv,files,consequences,scope,manual=False,app_targets=None):
  # The target and owning metadata must be unchanged between preview and the actual action.
  paths={str(p):identity(Path(p)) for p in set([target,Path(item['location'])]+([target.parent,self.home] if manual else [])+[Path(x) for x in files])}
  result=dict(action='manual' if manual else 'manager',manager=manager,target=str(target),scope=str(scope),argv=[str(a) for a in argv],
   title=('No verified manager: confirmed manual removal' if manual else 'Uninstall with '+manager),consequences=consequences+(' The selected object is first captured in a private recovery capsule and identity checked. Trash requires the same filesystem and has no Finder Put Back bookkeeping. Permanent deletion cannot be undone; an interrupted deletion may leave partial contents in the reported recovery capsule. These safeguards do not provide a transaction against hostile processes running as your same user.' if manual else ''),
   allowPermanent=manual,identities=paths,item=item,appTargets=sorted(app_targets or ([str(target)] if target.suffix=='.app' else [])),token='')
  result['token']=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
  return result

 def manager_or_manual(self,item,target,manager,argv,files,consequences,scope,app_targets=None):
  if argv and Path(argv[0]).is_file():
   if not os.access(argv[0],os.X_OK):raise Refused('Owning manager exists but is not executable. Repair it; deletion fallback is not automatic.')
   resolved=Path(argv[0]).resolve()
   trusted=self.brews+[self.home/'.local/bin',self.home/'.nvm/versions/node']
   if not any(root==resolved or root in resolved.parents for root in trusted):raise Refused('Manager executable resolves outside verified manager locations')
   files=files+[Path(argv[0])]
   if manager.startswith('npm'):files=files+[Path(argv[1])]
   return self.finish(item,target,manager,argv,files,consequences,scope,app_targets=app_targets)
  self.safe_tree(target)
  return self.finish(item,target,manager,[],files,
   'Owning manager is unavailable. Manual removal affects only the exact target and its contents. It does not update manager records, project manifests, lockfiles or command links; these may need manual repair. Other packages and data outside the target are retained. Prefer Trash for recovery.',scope,manual=True,app_targets=app_targets)

 def safe_tree(self,target):
  absolute=Path(os.path.abspath(target));canonical=target.resolve(strict=True)
  if target.is_symlink() or absolute!=canonical:raise Refused('Recursive removal cannot target a symlink or a path with linked ancestors')
  if canonical in [Path('/'),self.home,Path('/Applications'),self.home/'Applications',self.home/'.local/bin'] or len(canonical.parts)<4:
   raise Refused('Root or broad/shared directory is protected')
  if canonical.stat().st_uid!=os.getuid():raise Refused('Target is owned by another user; no elevation or forced deletion offered')
  if os.path.ismount(canonical):raise Refused('A mounted filesystem cannot be a manual removal target')
  # Reject nested mount points. rmtree never follows symbolic links; the OS provides fd-based traversal.
  if target.is_dir():
   if not getattr(shutil.rmtree,'avoids_symlink_attacks',False):raise Refused('This Python runtime lacks safe directory deletion support')
   device=canonical.stat().st_dev
   for base,dirs,files in os.walk(canonical,followlinks=False):
    for name in dirs:
     p=Path(base)/name
     if p.is_symlink():continue
     if p.stat().st_dev!=device or os.path.ismount(p):raise Refused('Nested filesystem/mount point prevents bounded removal')

 def plan(self,item):
  if not isinstance(item,dict) or not isinstance(item.get('location'),str):raise Refused('Inventory selection is invalid')
  path=Path(item['location'])
  if not path.is_absolute() or '..' in path.parts:raise Refused('Target must be an exact absolute path')
  if not path.exists():raise Refused('Stale inventory: target no longer exists. Refresh first.')
  real=path.resolve(strict=True)
  if item.get('scanIdentity') and item['scanIdentity']!=selection_identity(path):raise Refused('Stale inventory identity: target or alias changed. Refresh before removal.')
  if item.get('id') and not item['id'].startswith(str(real)+'|'):raise Refused('Stale canonical inventory target; refresh before removal')
  if item.get('kind')=='Executable candidate' and not item.get('scanIdentity'):raise Refused('This older executable-candidate snapshot has no identity fingerprint. Refresh before previewing removal.')
  if 'quantdinger' in str(real).lower():raise Refused('Active QuantDinger task is protected')
  if item.get('kind') in ['Dependency','Runtime','Apple app','Apple tool','Bundled app','Cache','Backup','Repository / project','Unclassified']:
   raise Refused('This is shared, system, bundled, cached, archived or unverified evidence; no removal adapter is offered.')
  if any(x.endswith('.app') for x in real.parent.parts):raise Refused('Bundled application contents must be removed through the owning app')
  if path.suffix=='.app':
   app=plistlib.loads(read_metadata(real/'Contents/Info.plist'))
   current=app.get('CFBundleShortVersionString') or app.get('CFBundleVersion')
   if current and item.get('version') not in ('Unknown',str(current)):raise Refused('Stale app version; refresh first')
   if str(app.get('CFBundleIdentifier','')).startswith('com.apple.'):raise Refused('Apple system app is protected')
   if app.get('CFBundleIdentifier')=='local.mac.inventory':raise Refused('This running inventory tool cannot uninstall itself')
  # Ownership comes from an actual keg/receipt or an exact cask artifact link, not the displayed name/source.
  for prefix in self.brews:
   try: relative=real.relative_to(prefix/'Cellar')
   except ValueError:relative=None
   if relative is not None and len(relative.parts)>=2:
    name,version=relative.parts[:2];valid_name(name)
    target=prefix/'Cellar'/name/version;receipt=target/'INSTALL_RECEIPT.json';d=metadata(receipt)
    if d.get('installed_on_request') is not True:raise Refused('Homebrew receipt marks this as a dependency, not a direct install')
    if any((prefix/'Cellar'/name/v).is_dir() for v in os.listdir(prefix/'Cellar'/name) if v!=version):raise Refused('Multiple installed kegs: removal scope is ambiguous')
    if name.startswith(('python','node','ruby','llvm','gcc','openssl')):raise Refused('Shared development runtime is protected')
    if item.get('source')=='Homebrew' and item.get('version') not in ('Unknown',version):raise Refused('Stale Homebrew version; refresh first')
    if (self.home/'Library/LaunchAgents'/('homebrew.mxcl.'+name+'.plist')).exists() or (Path('/Library/LaunchDaemons')/('homebrew.mxcl.'+name+'.plist')).exists():
     raise Refused('A Homebrew service registration exists. Stop/unregister that service with its manager before removing it.')
    files=self.reverse_brew(prefix,name)+[receipt]
    return self.manager_or_manual(item,target,'Homebrew formula',[prefix/'bin/brew','uninstall','--formula','--',name],files,
     'Removes this formula and its command links. No --force, --ignore-dependencies, autoremove, cleanup, or user-data zap.',prefix)
   matches=[]
   for cask in (prefix/'Caskroom').glob('*'):
    if not cask.is_dir():continue
    receipt=cask/'.metadata/INSTALL_RECEIPT.json'
    if not receipt.is_file():continue
    if real==cask.resolve() or cask in real.parents:matches.append((cask,receipt));continue
    if path.suffix=='.app':
     for artifact in cask.glob('*/*.app'):
      if artifact.is_symlink() and artifact.resolve()==real:matches.append((cask,receipt));break
   if len(matches)>1:raise Refused('More than one Homebrew cask claims this artifact; no removal offered')
   if matches:
    cask,receipt=matches[0];name=valid_name(cask.name);d=metadata(receipt)
    if d.get('installed_on_request') is not True:raise Refused('Cask is not verified as a direct install')
    files=self.reverse_brew(prefix,name)+[receipt]
    # A cask removal is wider than the app artifact; preview the manager-controlled scope.
    target=real if path.suffix=='.app' else cask
    if path.suffix=='.app':files.append(real/'Contents/Info.plist')
    apps=sorted({str(artifact.resolve()) for artifact in cask.glob('*/*.app') if artifact.is_symlink() and artifact.exists()})
    files += [Path(app)/'Contents/Info.plist' for app in apps if (Path(app)/'Contents/Info.plist').is_file()]
    return self.manager_or_manual(item,target,'Homebrew cask',[prefix/'bin/brew','uninstall','--cask','--',name],files,
     'Removes cask '+name+' and registered artifacts using Homebrew lifecycle rules. No --zap or forced deletion. Vendor uninstall hooks may run; app data is retained unless its normal uninstaller removes it.',cask,app_targets=apps)
  npm=self.npm_plan(item,path,real)
  if npm is not None:return npm
  uv=self.uv_plan(item,real)
  if uv is not None:return uv
  pip=self.pip_plan(item,real)
  if pip is not None:return pip
  # Manual fallback is limited to stand-alone app bundles in explicit app folders or single user command files.
  app_roots=[Path('/Applications'),self.home/'Applications',self.home/'Documents',self.home/'Desktop',self.home/'Downloads']
  app_scope=any(root==path.parent or (root!=Path('/Applications') and root in path.parents) for root in app_roots)
  if path.suffix=='.app' and app_scope:
   info=plistlib.loads(read_metadata(path/'Contents/Info.plist'))
   if str(info.get('CFBundleIdentifier','')).startswith('com.apple.'):raise Refused('Apple system app is protected')
   if any((path/marker).exists() for marker in ['.git','package.json','pyproject.toml','Cargo.toml','go.mod']):raise Refused('App-shaped project root is protected')
   exe=info.get('CFBundleExecutable','')
   if not isinstance(exe,str) or not exe or Path(exe).name!=exe or not (path/'Contents/MacOS'/exe).is_file() or not os.access(path/'Contents/MacOS'/exe,os.X_OK):raise Refused('The target is not a complete app bundle with a declared executable')
   if path.resolve() not in (path/'Contents/MacOS'/exe).resolve().parents:raise Refused('App executable is shared outside the bundle')
   self.safe_tree(path)
   return self.finish(item,path,'No verified manager',[],[path/'Contents/Info.plist',path/'Contents/MacOS'/exe],
    'No owning package manager was verified. Trash removes this app bundle only, leaving preferences, documents, helpers and system services intact. Permanent deletion is irreversible and does not perform a vendor uninstall.',path,manual=True)
  if path.parent in [self.home/'bin',self.home/'.local/bin'] and path.is_file() and not path.is_symlink():
   if path.name in ('uv','uvx','pip','pip3','npm','npx','node','brew') or path.name.startswith('python'):raise Refused('Shared manager/runtime command is protected')
   self.safe_tree(path)
   return self.finish(item,path,'No verified manager',[],[],
    'Removes only this standalone command file. Related packages, configuration and data are retained. Permanent deletion cannot be undone.',path,manual=True)
  raise Refused('No verified owning manager or safely bounded manual target. Project roots, environments, shared runtimes and arbitrary directories cannot be recursively deleted here.')

 def npm_plan(self,item,path,real):
  if 'node_modules' not in real.parts:return None
  index=real.parts.index('node_modules');after=real.parts[index+1:]
  if not after:return None
  if 'node_modules' in after:raise Refused('Nested npm dependency is not a top-level owned package')
  count=2 if after[0].startswith('@') else 1
  target=Path(*real.parts[:index+1+count]);root=Path(*real.parts[:index])
  ownership=[]
  d=self.npm_metadata(target/'package.json',ownership);name=valid_name(d.get('name'),npm=True)
  if Path(*after[:count]).as_posix()!=name:raise Refused('npm package name does not match its exact directory identity')
  if name in ('npm','corepack','node'):raise Refused(name+' is protected shared package-manager/runtime infrastructure. Choose the package you want to remove; this viewer does not remove Corepack or Node separately.')
  if item.get('name')==name and item.get('version') not in ('Unknown',str(d.get('version'))):raise Refused('Stale npm version; refresh first')
  if '/.codex/' in str(target) or '/.hermes/' in str(target) or any(x.endswith('.app') for x in target.parts):raise Refused('This package belongs to bundled agent/app infrastructure')
  nvm_prefix=root.parent.parent==self.home/'.nvm/versions/node'
  global_scope=root.name=='lib' and (root.parent in self.brews+[self.home/'.local',self.home/'.npm-global'] or nvm_prefix)
  scope=root.parent if global_scope else root
  files=ownership;declared=None
  if not global_scope:
   declared=metadata(root/'package.json');files.append(root/'package.json')
   if any((root/marker).exists() for marker in ['pnpm-lock.yaml','yarn.lock','bun.lock','bun.lockb','.pnp.cjs']):raise Refused('Another package manager has project ownership evidence; npm removal is not offered')
   pm=declared.get('packageManager','')
   if pm and not (isinstance(pm,str) and pm.startswith('npm@')):raise Refused('Project declares another package manager; its adapter is not supported')
   if not pm and not any((root/marker).is_file() for marker in ['package-lock.json','npm-shrinkwrap.json','node_modules/.package-lock.json']):raise Refused('No unambiguous npm ownership record; no manager is guessed from node_modules alone')
   if declared.get('workspaces'):raise Refused('Workspace-aware npm removal is not supported; ownership is ambiguous')
   for ancestor in root.parents:
    if ancestor==self.home.parent:break
    if (ancestor/'package.json').is_file() and metadata(ancestor/'package.json').get('workspaces'):raise Refused('Project is inside an npm workspace; removal is blocked')
   direct={k for key in ['dependencies','devDependencies','optionalDependencies'] for k in (declared.get(key) or {})}
   if name not in direct:raise Refused('This npm package is transitive or extraneous, not declared by the selected project')
   for filename in ['package-lock.json','npm-shrinkwrap.json']:
    lock=root/filename
    if lock.is_symlink():raise Refused('Linked npm lockfiles make removal scope ambiguous')
    if lock.is_file():files.append(lock)
   hidden=root/'node_modules/.package-lock.json'
   if hidden.is_symlink():raise Refused('Linked npm installation record is ambiguous')
   if hidden.is_file():files.append(hidden)
  peers=list(root.glob('node_modules/*/package.json'))+list(root.glob('node_modules/@*/*/package.json'))
  for p in peers:
   if p.parent.resolve()==target:continue
   peer=self.npm_metadata(p,files)
   if any(name in (peer.get(k) or {}) for k in ['dependencies','optionalDependencies','peerDependencies']):raise Refused('Another installed npm package declares this target; shared removal is blocked: '+str(p.parent))
  files+=peers
  candidates=([(scope/'bin/node',scope/'lib/node_modules/npm/bin/npm-cli.js')] if nvm_prefix else [])+self.npm_managers
  pair=next(((Path(node),Path(script)) for node,script in candidates if Path(node).is_file() and Path(script).is_file()),None)
  argv=[]
  if pair:
   node,script=pair
   trusted=self.brews+[self.home/'.nvm/versions/node']
   if not all(any(root in p.resolve().parents for root in trusted) for p in (node,script)):raise Refused('npm manager/runtime resolves outside verified installation locations')
   npm_identity=(script.parent.parent/'package.json').resolve(strict=True)
   if not any(root in npm_identity.parents for root in trusted):raise Refused('npm manager metadata resolves outside verified installation locations')
   npm_meta=metadata(npm_identity)
   if npm_meta.get('name')!='npm':raise Refused('npm manager identity could not be verified')
   files.append(npm_identity)
   argv=[node,script,'uninstall','--ignore-scripts','--no-audit','--no-fund','--save=true','--workspaces=false','--prefix',scope,'--global' if global_scope else '--global=false','--',name]
  return self.manager_or_manual(item,target,'npm global' if global_scope else 'npm project',argv,files,
   ('Removes only this prefix’s global package and its command links.' if global_scope else 'Changes this project’s package.json, lockfile and dependency tree; unused dependencies of the selected package may also be removed.')+' Package lifecycle scripts, audit and funding calls are disabled.',scope)

 def uv_plan(self,item,real):
  tools=self.home/'.local/share/uv/tools'
  try:relative=real.relative_to(tools)
  except ValueError:return None
  if not relative.parts:return None
  target=tools/relative.parts[0];receipt=target/'uv-receipt.toml'
  if not receipt.is_file():raise Refused('uv ownership receipt is absent')
  if receipt.is_symlink() or receipt.stat().st_size>4_000_000:raise Refused('uv receipt is linked or too large')
  text=read_metadata(receipt).decode();names=re.findall(r'requirements\s*=\s*\[\s*\{\s*name\s*=\s*"([^"]+)"\s*\}',text)
  if len(names)!=1:raise Refused('uv receipt format or tool ownership is ambiguous')
  name=valid_name(names[0]);selected=item.get('name','')
  if target.name!=normalized(name):raise Refused('uv tool directory is not the canonical receipt-owned tool name')
  if normalized(selected)!=normalized(name):raise Refused('This distribution is a dependency inside the uv tool, not the owned tool itself')
  if target.is_symlink():raise Refused('Linked tool environment is ambiguous')
  paths=[json.loads(value) for value in re.findall(r'install-path\s*=\s*("(?:[^"\\]|\\.)*")',text)]
  if not paths or any(Path(p).parent!=self.home/'.local/bin' for p in paths):raise Refused('uv entry-point locations are outside the verified user command directory')
  for link in paths:
   p=Path(link)
   if not p.is_symlink() or target/'bin' not in p.resolve().parents:raise Refused('uv entry point is shared, missing or no longer points into its owning tool environment')
  owned=list(target.glob('lib/python*/site-packages/'+name.replace('-','_')+'-*.dist-info/METADATA'))
  if len(owned)!=1:raise Refused('uv primary distribution identity is ambiguous')
  headers=package_headers(owned[0])
  if normalized(headers.get('Name',''))!=normalized(name) or item.get('version') not in ('Unknown',headers.get('Version')):raise Refused('Stale uv distribution identity; refresh first')
  return self.manager_or_manual(item,target,'uv tool',[self.home/'.local/bin/uv','tool','uninstall','--',name],[receipt,owned[0]]+[Path(p) for p in paths],
   'Removes this uv tool environment and its registered console entry points. Other uv tools and Python runtimes are retained.',tools)

 def pip_plan(self,item,real):
  if real.suffix!='.dist-info' or real.parent.name!='site-packages':return None
  env=real.parent.parent.parent.parent
  if any(part in ('.hermes','.codex','.openclaw') for part in env.parts):raise Refused('This environment belongs to agent/app infrastructure; use its owning installer, not per-package removal')
  if (env/'conda-meta').exists():raise Refused('This is a Conda-owned environment; no pip/uv manager is guessed')
  if not (env/'pyvenv.cfg').is_file():raise Refused('Only verified isolated virtual environments are supported for pip removal')
  requested=real/'REQUESTED'
  if not requested.is_file() or requested.is_symlink():raise Refused('No regular explicit-install marker: Python dependency removal is blocked')
  headers=package_headers(real/'METADATA')
  name=valid_name(normalized(headers.get('Name','')))
  if normalized(real.name.split('-',1)[0])!=name:raise Refused('Python distribution name does not match its exact metadata directory')
  if name in ('pip','setuptools','wheel'):raise Refused('Python packaging infrastructure is protected')
  version=headers.get('Version','Unknown')
  if item.get('version') not in ('Unknown',version):raise Refused('Stale Python package version; refresh first')
  files=[env/'pyvenv.cfg',real/'METADATA',requested]
  record=real/'RECORD'
  if not record.is_file() or record.is_symlink():raise Refused('Python RECORD ownership is unavailable or linked')
  def recorded(record_path):
   if record_path.stat().st_size>4_000_000:raise Refused('Python ownership record is too large')
   rows=list(csv.reader(io.StringIO(read_metadata(record_path).decode(),newline='')))
   result=set()
   for row in rows:
    if not row or not row[0]:continue
    owned=(real.parent/row[0]).resolve()
    if env.resolve() not in owned.parents:raise Refused('Python RECORD reaches outside the verified environment')
    result.add(owned)
   return result
  owned_files=recorded(record);files.append(record)
  for p in real.parent.glob('*.dist-info/METADATA'):
   if p.parent==real:continue
   other=package_headers(p)
   for requirement in other.get_all('Requires-Dist',[]):
    match=re.match(r'([A-Za-z0-9._-]+)',requirement)
    if match and normalized(match.group(1))==name:raise Refused('Another installed Python distribution requires this package: '+str(p.parent))
   files.append(p)
   other_record=p.parent/'RECORD'
   if other_record.is_file():
    if other_record.is_symlink():raise Refused('Another Python ownership record is linked')
    if owned_files & recorded(other_record):raise Refused('Python distributions share recorded files; automatic removal is blocked')
    files.append(other_record)
  installer=real/'INSTALLER'
  if not installer.is_file() or installer.is_symlink() or installer.stat().st_size>1000:raise Refused('Python installer provenance is unavailable; no manager is guessed')
  owner=read_metadata(installer,1000).decode().strip();files.append(installer)
  interpreter=env/'bin/python'
  if not interpreter.is_file():raise Refused('The environment lacks a verified interpreter')
  resolved=interpreter.resolve()
  trusted=[self.home/'.local/share/uv/python']+[prefix/'Cellar' for prefix in self.brews]+[Path('/Applications/Xcode.app/Contents/Developer'),Path('/Library/Frameworks/Python.framework')]
  if not any(parent==resolved or parent in resolved.parents for parent in trusted):raise Refused('Environment interpreter is not backed by a verified runtime location')
  if not (resolved.name.startswith('python') or resolved.name=='Python'):raise Refused('Interpreter target is not an identified Python runtime')
  files.append(interpreter)
  if owner=='uv':
   uv=self.home/'.local/bin/uv'
   if not uv.is_file() or not os.access(uv,os.X_OK):raise Refused('The owning uv manager is unavailable; per-package filesystem deletion is not safe')
   if not any(root in uv.resolve().parents for root in self.brews+[self.home/'.local/bin']):raise Refused('uv manager resolves outside verified manager locations')
   files.append(uv)
   return self.finish(item,real,'uv virtual environment',[uv,'pip','uninstall','--python',interpreter,'--',name],files,
    'Removes this explicitly installed uv distribution using the exact isolated interpreter/environment. Other distributions and the environment itself are retained; declared dependencies and shared recorded files were checked.',env)
  if owner!='pip':raise Refused('Python distribution declares an unsupported installer: no replacement manager is guessed')
  pip=list(real.parent.glob('pip-*.dist-info/METADATA'))
  if len(pip)!=1:raise Refused('The owning pip manager is unavailable; no filesystem fallback for shared Python package files')
  pip_headers=package_headers(pip[0])
  if pip_headers.get('Name')!='pip':raise Refused('pip distribution identity is invalid')
  files.append(pip[0])
  return self.finish(item,real,'pip virtual environment',[interpreter,'-I','-m','pip','--isolated','uninstall','--yes','--',name],files,
   'Uninstalls this explicitly installed distribution through this exact virtual environment. Other distributions and the environment itself are retained. Removal is blocked if another distribution declares a requirement. Running this environment’s Python and pip may execute installed startup hooks (.pth/sitecustomize) and pip implementation code; approve only if you trust this environment.',env)

 def revalidate(self,expected):
  fresh=self.plan(expected['item'])
  if fresh['token']!=expected.get('token'):raise Refused('Target, scope, owning metadata or manager changed since preview. Nothing was removed. Preview again.')
  return fresh

 def execute(self,expected,method,confirmation,runner=None,typed_confirmation=None):
  plan=self.revalidate(expected)
  if confirmation!=plan['token']:raise Refused('Explicit confirmation for this exact preview is required')
  target=Path(plan['target'])
  if method in ('permanent','trash'):
   if plan['action']!='manual':raise Refused('Use the verified owning manager for this package')
   if method=='permanent' and typed_confirmation!='DELETE '+target.name:raise Refused('Permanent deletion requires the exact typed confirmation')
   self.safe_tree(target)
   return manual_mutation(plan,method,self.home)
  if method=='verify-trash':raise Refused('Legacy path-only Trash is unavailable; preview the safe manual action again')
  if method!='manager' or plan['action']!='manager':raise Refused('Action does not match the confirmed plan')
  env={k:v for k,v in os.environ.items() if k in ['HOME','USER','LOGNAME','TMPDIR','LANG'] or k.startswith('LC_')}
  env.update(HOMEBREW_NO_AUTO_UPDATE='1',HOMEBREW_NO_INSTALL_CLEANUP='1',HOMEBREW_NO_ANALYTICS='1',PIP_DISABLE_PIP_VERSION_CHECK='1',PIP_CONFIG_FILE=os.devnull,UV_TOOL_DIR=str(self.home/'.local/share/uv/tools'),UV_TOOL_BIN_DIR=str(self.home/'.local/bin'))
  env['PATH']=os.pathsep.join([str(Path(plan['argv'][0]).parent),'/opt/homebrew/bin','/usr/local/bin','/usr/bin','/bin','/usr/sbin','/sbin'])
  result=(runner or run_manager)(plan['argv'],plan['scope'],env)
  if result.returncode!=0:return dict(success=False,output=result.output+'\nManager failed or was cancelled. No filesystem fallback was attempted.',target=plan['target'])
  exists=target.exists()
  if not exists and plan['manager']=='npm project':
   manifest=metadata(Path(plan['scope'])/'package.json');name=plan['argv'][-1]
   if any(name in (manifest.get(k) or {}) for k in ['dependencies','devDependencies','optionalDependencies']):
    return dict(success=False,output=result.output+'\nPackage directory is absent but its project declaration remains. Review/refresh; no forced removal was attempted.',target=plan['target'])
  return dict(success=not exists,output=result.output+('\nVerified target is absent.' if not exists else '\nManager exited successfully but target is still present. Refresh/review; no forced removal was attempted.'),target=plan['target'])

def run_manager(argv,cwd,env,on_output=None):
 # Install cancellation before launch: a signal during Popen must not orphan a new group.
 child=None;cancelled=[False];timer=[None]
 def signal_group(sig):
  if child is None:return
  try:os.killpg(child.pid,sig)
  except ProcessLookupError:pass
 def stop(signum,frame):
  cancelled[0]=True
  signal_group(signal.SIGTERM)
  if child is not None and timer[0] is None:
   timer[0]=threading.Timer(3,lambda:signal_group(signal.SIGKILL));timer[0].start()
 previous=signal.signal(signal.SIGTERM,stop)
 try:
  child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
  if cancelled[0]:stop(signal.SIGTERM,None)
  chunks=[];size=0;limit=1_000_000
  for line in iter(lambda:child.stdout.readline(8192),b''):
   if size<limit:chunks.append(line[:limit-size]);size+=len(chunks[-1])
   if on_output is not None:on_output(line.decode(errors='replace'))
   try:print(json.dumps({'progress':line.decode(errors='replace')[:2000]}),file=sys.stderr,flush=True)
   except BrokenPipeError:stop(signal.SIGTERM,None)
  code=child.wait()
 finally:
  # The leader may exit promptly while descendants ignore TERM and close their pipes.
  # Kill the owned group before cancelling escalation, even if the leader has exited.
  if cancelled[0]:signal_group(signal.SIGKILL)
  if timer[0] is not None:timer[0].cancel()
  if child is not None:
   if child.poll() is None:
    signal_group(signal.SIGTERM)
    try:child.wait(timeout=3)
    except subprocess.TimeoutExpired:
     signal_group(signal.SIGKILL);child.wait()
   child.stdout.close()
  signal.signal(signal.SIGTERM,previous)
 return type('ManagerResult',(),dict(returncode=code if not cancelled[0] else -15,output=b''.join(chunks).decode(errors='replace')))

if __name__=='__main__':
 try:
  request=json.loads(sys.stdin.read(2_000_000));planner=Planner()
  if sys.argv[1]=='plan':out=planner.plan(request['item'])
  else:
   method=request['method']
   if method=='permanent' and request.get('typedConfirmation')!='DELETE '+Path(request['plan']['target']).name:raise Refused('Permanent deletion requires the exact typed confirmation')
   out=planner.execute(request['plan'],method,request.get('confirmation'),typed_confirmation=request.get('typedConfirmation'))
  print(json.dumps(out))
 except Exception as error:
  message=str(error) if isinstance(error,Refused) else ('Removal could not complete ('+type(error).__name__+'). It may be partial; refresh/review. No automatic fallback or elevation was attempted.' if len(sys.argv)>1 and sys.argv[1]!='plan' else 'Cannot verify removal safely ('+type(error).__name__+'). Nothing changed.')
  print(json.dumps({'error':message}));sys.exit(1)

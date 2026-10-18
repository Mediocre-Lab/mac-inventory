"""Only synthetic metadata, mocked managers and temporary fixture deletion. Never installed software."""
import importlib.util, json, os, plistlib, shutil, tempfile, unittest, signal, sys, threading, time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('uninstall',Path(__file__).with_name('uninstall.py'))
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)

class RemovalTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
  self.home=self.root/'User home ü';self.home.mkdir()
  self.prefix=self.root/'opt/homebrew';self.prefix.mkdir(parents=True)
  self.node=self.prefix/'bin/node';self.node.parent.mkdir();self.node.write_text('MOCK ONLY');self.node.chmod(0o755)
  self.npm=self.prefix/'lib/node_modules/npm/bin/npm-cli.js';self.npm.parent.mkdir(parents=True);self.npm.write_text('MOCK ONLY')
  (self.npm.parent.parent/'package.json').write_text('{"name":"npm","version":"10.9.8"}')
  self.brew=self.prefix/'bin/brew';self.brew.write_text('MOCK ONLY');self.brew.chmod(0o755)
  self.planner=u.Planner(home=self.home,brew_prefixes=[self.prefix],npm_managers=[(self.node,self.npm)])
 def tearDown(self):self.temp.cleanup()
 def item(self,path,name='demo',kind='CLI / tool',source='Fixture',version='1.0'):
  return dict(location=str(path),name=name,kind=kind,source=source,version=version,id=str(path.resolve())+'|'+name)
 def formula(self,name='demo',direct=True):
  p=self.prefix/'Cellar'/name/'1.0';p.mkdir(parents=True)
  (p/'INSTALL_RECEIPT.json').write_text(json.dumps({'installed_on_request':direct,'runtime_dependencies':[]}))
  return p
 def package(self,root,name='@team/demo',global_scope=False):
  p=root/'node_modules'/name;p.mkdir(parents=True)
  (p/'package.json').write_text(json.dumps({'name':name,'version':'1.0','bin':{'demo':'cli.js'}}))
  if not global_scope:
   (root/'package.json').write_text(json.dumps({'dependencies':{name:'1.0'}}))
   (root/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'node_modules/'+name:{'version':'1.0'}}}))
  return p
 def app(self,name='Example ü; $(echo nope).app'):
  p=self.home/'Applications'/name;(p/'Contents').mkdir(parents=True)
  (p/'Contents/MacOS').mkdir();(p/'Contents/MacOS/Fixture').write_text('MOCK ONLY');(p/'Contents/MacOS/Fixture').chmod(0o755)
  with (p/'Contents/Info.plist').open('wb') as f:plistlib.dump({'CFBundleIdentifier':'test.example','CFBundleShortVersionString':'1.0','CFBundleExecutable':'Fixture','CFBundlePackageType':'APPL'},f)
  return p
 def test_metadata_fifo_and_link_reads_are_refused_without_blocking(self):
  self.assertEqual(self.root.parent,Path(tempfile.gettempdir()).resolve())
  fifo=self.root/'metadata-fifo';os.mkfifo(fifo)
  for reader in (u.read_metadata,u.metadata,u.package_headers):
   with self.assertRaises(u.Refused):reader(fifo)
  regular=self.root/'regular.json';regular.write_text('{}');linked=self.root/'linked.json';linked.symlink_to(regular)
  with self.assertRaises(OSError):u.read_metadata(linked)
  self.assertEqual(u.read_metadata(regular),b'{}')
  with self.assertRaises(u.Refused):u.read_metadata(regular,1)
 def test_app_plist_fifo_is_refused_without_blocking(self):
  app=self.app();plist=app/'Contents/Info.plist';self.assertIn(self.root,plist.resolve().parents)
  plist.unlink();os.mkfifo(plist)
  with self.assertRaises(u.Refused):self.planner.plan(self.item(app,kind='App'))
 def test_pip_record_preserves_quoted_filename_newlines_for_shared_ownership(self):
  env,dist,site=self.pip_fixture()
  # These are distinct valid filenames; stripping CSV newlines invents overlap.
  filename='quoted\nname.py';owned=site/filename;distinct=site/'quotedname.py'
  for path in (owned,distinct):
   self.assertIn(self.root,path.resolve().parents);path.write_text('MOCK ONLY')
  import csv,io
  def record(filename):
   encoded=io.StringIO(newline='');csv.writer(encoded).writerow([filename,'','']);return encoded.getvalue()
  (dist/'RECORD').write_text(record(filename))
  other=site/'other-1.dist-info';other.mkdir()
  (other/'METADATA').write_text('Name: other\nVersion: 1\n')
  (other/'RECORD').write_text(record(distinct.name))
  self.assertEqual(self.planner.plan(self.item(dist,kind='Library'))['manager'],'pip virtual environment')
  # The same newline-bearing file through another spelling is genuinely shared.
  (other/'RECORD').write_text(record('./'+filename))
  with self.assertRaisesRegex(u.Refused,'share recorded files'):
   self.planner.plan(self.item(dist,kind='Library'))
 def test_pip_record_fifo_is_refused_without_blocking(self):
  env,dist,site=self.pip_fixture();record=dist/'RECORD';self.assertIn(self.root,record.resolve().parents)
  record.unlink();os.mkfifo(record)
  with self.assertRaises(u.Refused):self.planner.plan(self.item(dist,kind='Library'))
 def test_brew_uses_receipt_not_display_name(self):
  p=self.formula();plan=self.planner.plan(self.item(p,name='arbitrary displayed alias',source='Made up'))
  self.assertEqual(plan['argv'],[str(self.brew),'uninstall','--formula','--','demo'])
  self.assertFalse(plan['allowPermanent'])
 def test_brew_transitive_refused(self):
  p=self.formula(direct=False)
  with self.assertRaises(u.Refused):self.planner.plan(self.item(p))
 def test_brew_shared_dependency_refused(self):
  p=self.formula();other=self.formula('other')
  (other/'INSTALL_RECEIPT.json').write_text(json.dumps({'installed_on_request':True,'runtime_dependencies':[{'full_name':'demo'}]}))
  with self.assertRaisesRegex(u.Refused,'Shared dependency'):self.planner.plan(self.item(p))
 def test_manager_failure_never_forces_delete(self):
  p=self.formula();plan=self.planner.plan(self.item(p));runner=Mock(return_value=SimpleNamespace(returncode=1,output='mock failure'))
  result=self.planner.execute(plan,'manager',plan['token'],runner=runner)
  self.assertFalse(result['success']);self.assertTrue(p.exists());self.assertIn('No filesystem fallback',result['output'])
  with self.assertRaises(u.Refused):self.planner.execute(plan,'permanent',plan['token'],typed_confirmation='DELETE 1.0')
 def test_success_is_verified_not_assumed(self):
  p=self.formula();plan=self.planner.plan(self.item(p));runner=Mock(return_value=SimpleNamespace(returncode=0,output='mock says success'))
  self.assertFalse(self.planner.execute(plan,'manager',plan['token'],runner=runner)['success']);self.assertTrue(p.exists())
 def test_mock_manager_removal_is_verified(self):
  p=self.formula();plan=self.planner.plan(self.item(p))
  def mock(argv,cwd,env):
   self.assertEqual(argv[-1],'demo');self.assertEqual(cwd,str(self.prefix));self.assertEqual(env['HOMEBREW_NO_AUTO_UPDATE'],'1')
   shutil.rmtree(p);return SimpleNamespace(returncode=0,output='mock fixture removed')
  self.assertTrue(self.planner.execute(plan,'manager',plan['token'],runner=mock)['success'])
 def test_stale_metadata_and_replaced_target_refused(self):
  p=self.formula();plan=self.planner.plan(self.item(p));(p/'INSTALL_RECEIPT.json').write_text('{"installed_on_request":true,"runtime_dependencies":[],"changed":1}')
  runner=Mock()
  with self.assertRaises(u.Refused):self.planner.execute(plan,'manager',plan['token'],runner=runner)
  runner.assert_not_called()
 def test_confirm_token_is_required(self):
  p=self.formula();plan=self.planner.plan(self.item(p));runner=Mock()
  with self.assertRaises(u.Refused):self.planner.execute(plan,'manager','yes',runner=runner)
  runner.assert_not_called();self.assertTrue(p.exists())
 def test_global_npm_exact_scope_and_scoped_argv(self):
  p=self.package(self.prefix/'lib',global_scope=True);plan=self.planner.plan(self.item(p,name='@team/demo'))
  self.assertEqual(plan['manager'],'npm global');self.assertEqual(plan['scope'],str(self.prefix))
  self.assertEqual(plan['argv'][-2:],['--','@team/demo']);self.assertIn('--ignore-scripts',plan['argv'])
 def test_project_npm_space_unicode_scope(self):
  root=self.home/'Projects/Project with spaces ü';root.mkdir(parents=True)
  p=self.package(root);plan=self.planner.plan(self.item(p,name='@team/demo'))
  self.assertEqual(plan['manager'],'npm project');self.assertEqual(plan['scope'],str(root));self.assertIn('--global=false',plan['argv'])
 def test_transitive_npm_and_workspace_refused(self):
  root=self.home/'project';root.mkdir();p=self.package(root)
  (root/'package.json').write_text('{"dependencies":{}}')
  with self.assertRaises(u.Refused):self.planner.plan(self.item(p,name='@team/demo'))
  (root/'package.json').write_text('{"dependencies":{"@team/demo":"1"},"workspaces":["packages/*"]}')
  with self.assertRaises(u.Refused):self.planner.plan(self.item(p,name='@team/demo'))
 def test_shared_npm_dependency_refused(self):
  root=self.home/'project';root.mkdir();p=self.package(root);peer=root/'node_modules/peer';peer.mkdir()
  (peer/'package.json').write_text('{"name":"peer","dependencies":{"@team/demo":"1.0"}}')
  with self.assertRaisesRegex(u.Refused,'Another installed npm'):self.planner.plan(self.item(p,name='@team/demo'))
 def test_invalid_option_like_package_refused(self):
  root=self.home/'project';root.mkdir();p=self.package(root,'demo')
  (p/'package.json').write_text('{"name":"--force","version":"1.0"}')
  with self.assertRaises(u.Refused):self.planner.plan(self.item(p))
 def test_unmanaged_app_has_confirmed_manual_plan(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App',source='Homebrew'))
  self.assertEqual(plan['action'],'manual');self.assertEqual(plan['argv'],[]);self.assertTrue(plan['allowPermanent'])
 def test_permanent_requires_exact_confirmation_and_preserves_symlink_target(self):
  p=self.app();outside=self.root/'outside';outside.mkdir();(outside/'keep').write_text('KEEP')
  (p/'linked').symlink_to(outside,target_is_directory=True)
  plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  with self.assertRaises(u.Refused):self.planner.execute(plan,'permanent',plan['token'])
  self.assertIn(self.root,p.resolve().parents)
  result=self.planner.execute(plan,'permanent',plan['token'],typed_confirmation='DELETE '+p.name)
  self.assertTrue(result['success']);self.assertFalse(p.exists());self.assertTrue((outside/'keep').exists())
 def test_symlink_and_project_root_permanent_fallback_refused(self):
  target=self.app();linked=self.home/'Applications/Linked.app';linked.symlink_to(target,target_is_directory=True)
  with self.assertRaises(u.Refused):self.planner.plan(self.item(linked,name='Linked',kind='App'))
  with self.assertRaises(u.Refused):self.planner.plan(self.item(self.home,kind='App'))
 def test_old_or_stale_candidate_refused(self):
  p=self.home/'bin/tool';p.parent.mkdir();p.write_text('MOCK');p.chmod(0o755);item=self.item(p,kind='Executable candidate',version='Unknown')
  with self.assertRaises(u.Refused):self.planner.plan(item)
  item['scanIdentity']=u.selection_identity(p);p.write_text('CHANGED')
  with self.assertRaisesRegex(u.Refused,'Stale inventory identity'):self.planner.plan(item)
 def test_missing_manager_offers_confirmed_manual_plan_without_mutation(self):
  p=self.formula();self.brew.unlink();plan=self.planner.plan(self.item(p))
  self.assertEqual(plan['action'],'manual');self.assertTrue(p.exists())
 def test_cask_ownership_exact_artifact_link(self):
  p=self.app('Cask Example.app');cask=self.prefix/'Caskroom/example';(cask/'1.0').mkdir(parents=True)
  (cask/'1.0'/p.name).symlink_to(p,target_is_directory=True);(cask/'.metadata').mkdir()
  (cask/'.metadata/INSTALL_RECEIPT.json').write_text('{"installed_on_request":true,"runtime_dependencies":{}}')
  plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  self.assertEqual(plan['argv'][-3:],['--cask','--','example'])
 def test_trash_execution_is_disabled_without_mutation(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  with self.assertRaisesRegex(u.Refused,'Legacy'):self.planner.execute(plan,'verify-trash',plan['token'])
  self.assertTrue(p.exists())
 def confined_manual(self,plan,method,typed=True):
  target=Path(plan['target']);self.assertIn(self.root,target.resolve().parents)
  self.assertIn(self.root,self.home.resolve().parents)
  return self.planner.execute(plan,method,plan['token'],typed_confirmation='DELETE '+target.name if typed else None)
 def test_manual_trash_preserves_unicode_name_and_existing_collision(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  trash=self.home/'.Trash';trash.mkdir(mode=0o700);existing=trash/p.name;existing.write_text('KEEP')
  # Trash creation changes HOME metadata, so preview the current proof again.
  plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  result=self.confined_manual(plan,'trash')
  self.assertTrue(result['success']);self.assertFalse(p.exists());self.assertEqual(existing.read_text(),'KEEP')
  moved=[x for x in trash.iterdir() if x!=existing]
  self.assertEqual(len(moved),1);self.assertTrue((moved[0]/'Contents/Info.plist').is_file())
  self.assertIn('no Finder Put Back',result['output'])
  self.assertEqual(list(p.parent.glob('.mac-inventory-removal-*')),[])
 def test_manual_capture_replaced_root_restores_without_deleting_either(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=u.rename_exclusive;held=p.parent/'original-held'
  self.assertIn(self.root,held.resolve().parents)
  def replacement(source_fd,source,destination_fd,destination):
   if source==p.name and destination=='target':
    os.rename(source,'original-held',src_dir_fd=source_fd,dst_dir_fd=source_fd)
    os.mkdir(source,dir_fd=source_fd)
   return original(source_fd,source,destination_fd,destination)
  with patch.object(u,'rename_exclusive',side_effect=replacement):
   with self.assertRaisesRegex(u.Refused,'replaced during capture'):self.confined_manual(plan,'permanent')
  self.assertTrue((held/'Contents/Info.plist').is_file());self.assertTrue(p.is_dir())
  self.assertEqual(list(p.parent.glob('.mac-inventory-removal-*')),[])
 def test_manual_parent_real_directory_replacement_is_refused(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=u.AnchoredDirectories.open
  held=p.parent.with_name('Applications-held');self.assertIn(self.root,held.resolve().parents)
  def changed_parent(anchors,path):
   if Path(path)==p.parent:
    p.parent.rename(held);p.parent.mkdir();p.mkdir()
   return original(anchors,path)
  with patch.object(u.AnchoredDirectories,'open',new=changed_parent):
   with self.assertRaisesRegex(u.Refused,'parent directory changed'):self.confined_manual(plan,'permanent')
  self.assertTrue((held/p.name/'Contents/Info.plist').exists());self.assertTrue(p.exists())
 def test_manual_parent_symlink_replacement_is_refused(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=u.AnchoredDirectories.open
  held=p.parent.with_name('Applications-held');outside=self.root/'outside-safe';outside.mkdir();(outside/'keep').write_text('KEEP')
  for path in (held,outside):self.assertIn(self.root,path.resolve().parents)
  def changed_parent(anchors,path):
   if Path(path)==p.parent:
    p.parent.rename(held);p.parent.symlink_to(outside,target_is_directory=True)
   return original(anchors,path)
  with patch.object(u.AnchoredDirectories,'open',new=changed_parent):
   with self.assertRaises(OSError):self.confined_manual(plan,'permanent')
  self.assertTrue((held/p.name/'Contents/Info.plist').exists());self.assertEqual((outside/'keep').read_text(),'KEEP')
 def test_manual_trash_symlink_is_refused_and_target_restored(self):
  p=self.app();outside=self.root/'outside-safe';outside.mkdir();(outside/'keep').write_text('KEEP')
  self.assertIn(self.root,outside.resolve().parents);(self.home/'.Trash').symlink_to(outside,target_is_directory=True)
  plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  with self.assertRaisesRegex(u.Refused,'restored'):self.confined_manual(plan,'trash')
  self.assertTrue((p/'Contents/Info.plist').exists());self.assertEqual((outside/'keep').read_text(),'KEEP')
 def test_manual_helper_rejects_unknown_method_without_mutation(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));self.assertIn(self.root,p.resolve().parents)
  with self.assertRaisesRegex(u.Refused,'Unsupported'):u.manual_mutation(plan,'unexpected',self.home)
  self.assertTrue(p.exists())
 def test_manual_missing_exclusive_rename_support_preserves_target(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'))
  with patch.object(u,'rename_exclusive',side_effect=u.Refused('Exclusive rename unavailable')):
   with self.assertRaisesRegex(u.Refused,'unavailable'):self.confined_manual(plan,'permanent')
  self.assertTrue((p/'Contents/Info.plist').exists());self.assertEqual(list(p.parent.glob('.mac-inventory-removal-*')),[])
 def test_manual_cancel_after_capture_restores_complete_target(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=u.rename_exclusive
  def cancel_after_capture(source_fd,source,destination_fd,destination):
   result=original(source_fd,source,destination_fd,destination)
   if source==p.name and destination=='target':os.kill(os.getpid(),signal.SIGTERM)
   return result
  with patch.object(u,'rename_exclusive',side_effect=cancel_after_capture):
   with self.assertRaisesRegex(u.Refused,'cancelled.*restored'):self.confined_manual(plan,'permanent')
  self.assertTrue((p/'Contents/Info.plist').exists());self.assertEqual(list(p.parent.glob('.mac-inventory-removal-*')),[])
 def test_manual_partial_cancel_preserves_journal_and_remaining_data(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=os.unlink;changed=[]
  def cancel_after_leaf(name,*args,**kwargs):
   result=original(name,*args,**kwargs)
   if name!='recovery.json' and not changed:
    changed.append(name);os.kill(os.getpid(),signal.SIGTERM)
   return result
  with patch.object(u.os,'unlink',side_effect=cancel_after_leaf):
   with self.assertRaisesRegex(u.Refused,'partial.*Recovery:'):self.confined_manual(plan,'permanent')
  self.assertFalse(p.exists());capsules=list(p.parent.glob('.mac-inventory-removal-*'));self.assertEqual(len(capsules),1)
  journal=json.loads((capsules[0]/'recovery.json').read_text())
  self.assertEqual(journal['originalPath'],str(p));self.assertEqual(journal['method'],'permanent')
  self.assertTrue((capsules[0]/'target').is_dir())
 def test_manual_trash_exdev_restores_and_does_not_copy(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=u.rename_exclusive
  calls=[]
  def fail_trash_once(source_fd,source,destination_fd,destination):
   if source=='target' and not calls:
    calls.append(True);raise OSError(18,'Cross-device link')
   return original(source_fd,source,destination_fd,destination)
  with patch.object(u,'rename_exclusive',side_effect=fail_trash_once):
   with self.assertRaisesRegex(u.Refused,'restored'):self.confined_manual(plan,'trash')
  self.assertTrue((p/'Contents/Info.plist').exists());self.assertEqual(list((self.home/'.Trash').iterdir()),[])
 def test_manual_restore_collision_preserves_capsule_and_new_original(self):
  p=self.app();plan=self.planner.plan(self.item(p,name=p.stem,kind='App'));original=u.rename_exclusive
  def block_restore(source_fd,source,destination_fd,destination):
   result=original(source_fd,source,destination_fd,destination)
   if source==p.name and destination=='target':
    os.mkdir(p.name,dir_fd=source_fd);os.kill(os.getpid(),signal.SIGTERM)
   return result
  with patch.object(u,'rename_exclusive',side_effect=block_restore):
   with self.assertRaisesRegex(u.Refused,'all captured data was preserved.*Recovery:'):self.confined_manual(plan,'permanent')
  self.assertTrue(p.is_dir());capsules=list(p.parent.glob('.mac-inventory-removal-*'));self.assertEqual(len(capsules),1)
  self.assertTrue((capsules[0]/'target/Contents/Info.plist').exists());self.assertTrue((capsules[0]/'recovery.json').exists())
 def test_system_runtime_and_dependency_selections_blocked(self):
  p=self.formula()
  for kind in ['Dependency','Runtime','Apple tool','Bundled app','Repository / project']:
   with self.assertRaises(u.Refused):self.planner.plan(self.item(p,kind=kind))
 def uv_fixture(self):
  target=self.home/'.local/share/uv/tools/demo';dist=target/'lib/python3.12/site-packages/demo-1.0.dist-info';dist.mkdir(parents=True)
  (dist/'METADATA').write_text('Name: demo\nVersion: 1.0\n')
  binary=target/'bin/demo';binary.parent.mkdir();binary.write_text('MOCK ONLY')
  link=self.home/'.local/bin/demo';link.parent.mkdir(parents=True);link.symlink_to(binary)
  uv=link.parent/'uv';uv.write_text('MOCK ONLY');uv.chmod(0o755)
  (target/'uv-receipt.toml').write_text('[tool]\nrequirements = [{ name = "demo" }]\nentrypoints = [{ name = "demo", install-path = '+json.dumps(str(link))+', from = "demo" }]\n')
  return target,dist,link
 def test_uv_uses_exact_owned_receipt_and_entry_point(self):
  target,dist,link=self.uv_fixture();plan=self.planner.plan(self.item(dist))
  self.assertEqual(plan['manager'],'uv tool');self.assertEqual(plan['target'],str(target));self.assertEqual(plan['argv'][-2:],['--','demo'])
 def test_uv_changed_shared_entry_point_is_refused(self):
  target,dist,link=self.uv_fixture();plan=self.planner.plan(self.item(dist));other=self.home/'other';other.write_text('KEEP')
  link.unlink();link.symlink_to(other)
  with self.assertRaises(u.Refused):self.planner.execute(plan,'manager',plan['token'],runner=Mock())
  self.assertTrue(other.exists())
 def pip_fixture(self):
  env=self.home/'project/.venv';site=env/'lib/python3.12/site-packages';dist=site/'demo-1.0.dist-info';dist.mkdir(parents=True)
  (env/'pyvenv.cfg').write_text('version = 3.12.0\n')
  (dist/'METADATA').write_text('Name: demo\nVersion: 1.0\n');(dist/'REQUESTED').touch();(dist/'INSTALLER').write_text('pip\n')
  (site/'demo.py').write_text('MOCK ONLY');(dist/'RECORD').write_text('demo.py,,\ndemo-1.0.dist-info/METADATA,,\n')
  pip=site/'pip-24.dist-info';pip.mkdir();(pip/'METADATA').write_text('Name: pip\nVersion: 24\n');(pip/'RECORD').write_text('pip-24.dist-info/METADATA,,\n')
  runtime=self.prefix/'Cellar/python@3.12/1/bin/python3.12';runtime.parent.mkdir(parents=True);runtime.write_text('MOCK ONLY');runtime.chmod(0o755)
  binary=env/'bin/python';binary.parent.mkdir();binary.symlink_to(runtime)
  return env,dist,site
 def test_pip_exact_environment_and_isolated_argv(self):
  env,dist,site=self.pip_fixture();plan=self.planner.plan(self.item(dist,kind='Library'))
  self.assertEqual(plan['manager'],'pip virtual environment');self.assertEqual(plan['argv'],[str(env/'bin/python'),'-I','-m','pip','--isolated','uninstall','--yes','--','demo'])
  self.assertFalse(plan['allowPermanent'])
 def test_pip_preview_discloses_environment_startup_code_trust_boundary(self):
  env,dist,site=self.pip_fixture();plan=self.planner.plan(self.item(dist,kind='Library'))
  self.assertIn('startup hooks (.pth/sitecustomize)',plan['consequences'])
  self.assertIn('pip implementation code',plan['consequences'])
  self.assertIn('approve only if you trust this environment',plan['consequences'])
 def test_pip_uninstall_disables_config_that_can_add_unselected_packages(self):
  env,dist,site=self.pip_fixture();plan=self.planner.plan(self.item(dist,kind='Library'))
  config=self.home/'.pip/pip.conf';config.parent.mkdir();requirements=self.home/'extra.txt'
  self.assertEqual(requirements.resolve().parent,self.home.resolve())
  requirements.write_text('unselected-package\n');config.write_text('[uninstall]\nrequirement = '+str(requirements)+'\n')
  def runner(argv,cwd,environment):
   self.assertIn('--isolated',argv);self.assertEqual(environment['PIP_CONFIG_FILE'],os.devnull)
   self.assertEqual(argv[-2:],['--','demo'])
   return SimpleNamespace(returncode=1,output='MOCK ONLY: config isolation verified')
  self.assertFalse(self.planner.execute(plan,'manager',plan['token'],runner=runner)['success'])
  self.assertTrue(dist.exists());self.assertEqual(requirements.read_text(),'unselected-package\n')
 def test_pip_record_escape_and_shared_files_are_refused(self):
  env,dist,site=self.pip_fixture();(dist/'RECORD').write_text('../../../../../../user-file,,\n')
  with self.assertRaises(u.Refused):self.planner.plan(self.item(dist,kind='Library'))
  (dist/'RECORD').write_text('demo.py,,\n');other=site/'other-1.dist-info';other.mkdir();(other/'METADATA').write_text('Name: other\nVersion: 1\n');(other/'RECORD').write_text('demo.py,,\n')
  with self.assertRaisesRegex(u.Refused,'share recorded files'):self.planner.plan(self.item(dist,kind='Library'))
 def test_pip_reverse_requirement_is_refused(self):
  env,dist,site=self.pip_fixture();other=site/'other-1.dist-info';other.mkdir();(other/'METADATA').write_text('Name: other\nRequires-Dist: demo>=1\n')
  with self.assertRaisesRegex(u.Refused,'requires this package'):self.planner.plan(self.item(dist,kind='Library'))
 def test_cancelled_mock_manager_preserves_target_no_fallback(self):
  p=self.formula();plan=self.planner.plan(self.item(p));runner=Mock(return_value=SimpleNamespace(returncode=-15,output='mock cancellation'))
  result=self.planner.execute(plan,'manager',plan['token'],runner=runner)
  self.assertFalse(result['success']);self.assertTrue(p.exists());self.assertIn('cancelled',result['output'])
 def test_manager_retargeted_outside_trusted_prefix_is_refused(self):
  p=self.formula();outside=self.home/'untrusted';outside.write_text('NEVER RUN');outside.chmod(0o755)
  self.brew.unlink();self.brew.symlink_to(outside)
  with self.assertRaisesRegex(u.Refused,'outside verified manager'):self.planner.plan(self.item(p))
 def test_stale_app_version_is_refused(self):
  p=self.app()
  with self.assertRaisesRegex(u.Refused,'Stale app version'):self.planner.plan(self.item(p,kind='App',version='0.1'))
 def test_app_shaped_project_root_is_refused(self):
  p=self.app();(p/'.git').mkdir()
  with self.assertRaisesRegex(u.Refused,'project root'):self.planner.plan(self.item(p,kind='App'))
 def test_owned_synthetic_manager_process_cancels_and_captures_output(self):
  timer=threading.Timer(0.05,lambda:os.kill(os.getpid(),signal.SIGTERM))
  try:
   result=u.run_manager([sys.executable,'-I','-B','-c','import time; print("SYNTHETIC FIXTURE LOG", flush=True); time.sleep(5)'],str(self.root),{'PATH':'/usr/bin:/bin'},on_output=lambda line:timer.start())
  finally:timer.cancel()
  self.assertEqual(result.returncode,-15);self.assertIn('SYNTHETIC FIXTURE LOG',result.output)
 def test_cancel_during_process_creation_stops_new_owned_group(self):
  self.assertEqual(self.root.parent,Path(tempfile.gettempdir()).resolve())
  marker=self.root/'startup-survived';self.assertEqual(marker.resolve().parent,self.root)
  original=u.subprocess.Popen
  def launch_after_cancel(*args,**kwargs):
   os.kill(os.getpid(),signal.SIGTERM)
   return original(*args,**kwargs)
  with patch.object(u.subprocess,'Popen',side_effect=launch_after_cancel):
   result=u.run_manager([sys.executable,'-I','-B','-c',"import time,pathlib,sys;time.sleep(.3);pathlib.Path(sys.argv[1]).write_text('SURVIVED')",str(marker)],str(self.root),{'PATH':'/usr/bin:/bin'})
  self.assertEqual(result.returncode,-15)
  time.sleep(.4);self.assertFalse(marker.exists())
 def test_cancel_kills_detached_stdio_descendant_after_leader_exits(self):
  # Only authored processes and files beneath this disposable fixture are used.
  self.assertEqual(self.root.parent,Path(tempfile.gettempdir()).resolve())
  marker=self.root/'descendant-survived';ready=self.root/'descendant-ready'
  for path in (marker,ready):self.assertEqual(path.resolve().parent,self.root)
  descendant="import signal,time,sys,pathlib; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(.6); pathlib.Path(sys.argv[2]).write_text('SURVIVED')"
  parent="import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[1],sys.argv[2],sys.argv[3]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);\nwhile not pathlib.Path(sys.argv[2]).exists(): time.sleep(.005)\nprint(p.pid,flush=True); time.sleep(10)"
  owned=[]
  def cancel(line):
   owned.append(int(line.strip()));os.kill(os.getpid(),signal.SIGTERM)
  try:
   result=u.run_manager([sys.executable,'-I','-B','-c',parent,descendant,str(ready),str(marker)],str(self.root),{'PATH':'/usr/bin:/bin'},on_output=cancel)
   self.assertEqual(result.returncode,-15);self.assertEqual(len(owned),1)
   time.sleep(.8)
   self.assertFalse(marker.exists(),'An owned descendant continued after cancellation returned')
  finally:
   for pid in owned:
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
 def test_pnpm_and_unknown_npm_project_ownership_refused(self):
  root=self.home/'project';root.mkdir();p=self.package(root);(root/'pnpm-lock.yaml').write_text('fixture')
  with self.assertRaisesRegex(u.Refused,'Another package manager'):self.planner.plan(self.item(p,name='@team/demo'))
  (root/'pnpm-lock.yaml').unlink();(root/'package-lock.json').unlink()
  with self.assertRaisesRegex(u.Refused,'No unambiguous npm'):self.planner.plan(self.item(p,name='@team/demo'))
 def test_uv_distribution_uses_uv_instead_of_pip(self):
  env,dist,site=self.pip_fixture();(dist/'INSTALLER').write_text('uv\n');uv=self.home/'.local/bin/uv';uv.parent.mkdir(parents=True);uv.write_text('MOCK ONLY');uv.chmod(0o755)
  plan=self.planner.plan(self.item(dist,kind='Library'))
  self.assertEqual(plan['manager'],'uv virtual environment');self.assertEqual(plan['argv'],[str(uv),'pip','uninstall','--python',str(env/'bin/python'),'--','demo'])
 def test_unknown_python_installer_is_refused(self):
  env,dist,site=self.pip_fixture();(dist/'INSTALLER').write_text('unknown\n')
  with self.assertRaisesRegex(u.Refused,'unsupported installer'):self.planner.plan(self.item(dist,kind='Library'))
 def test_conda_environment_is_not_routed_to_pip(self):
  env,dist,site=self.pip_fixture();(env/'conda-meta').mkdir()
  with self.assertRaisesRegex(u.Refused,'Conda-owned'):self.planner.plan(self.item(dist,kind='Library'))
 def linked_corepack_fixture(self,requires=None):
  keg=self.formula('node@22');manifest=keg/'lib/node_modules/corepack/package.json';manifest.parent.mkdir(parents=True)
  manifest.write_text(json.dumps({'name':'corepack','version':'1.0','dependencies':requires or {}}))
  peer=self.prefix/'lib/node_modules/corepack';peer.mkdir();(peer/'package.json').symlink_to(manifest)
  return peer,manifest
 def test_homebrew_linked_peer_manifest_unblocks_unrelated_npm_package(self):
  target=self.package(self.prefix/'lib',name='demo',global_scope=True);peer,manifest=self.linked_corepack_fixture()
  plan=self.planner.plan(self.item(target))
  self.assertEqual(plan['manager'],'npm global');self.assertIn(str(manifest),plan['identities']);self.assertIn(str(peer/'package.json'),plan['identities'])
 def test_linked_corepack_itself_remains_protected(self):
  peer,manifest=self.linked_corepack_fixture()
  with self.assertRaisesRegex(u.Refused,'protected shared'):self.planner.plan(self.item(peer,name='corepack'))
 def test_linked_peer_cannot_escape_owner_prefix_or_forge_package_name(self):
  target=self.package(self.prefix/'lib',name='demo',global_scope=True);peer,manifest=self.linked_corepack_fixture()
  manifest.write_text('{"name":"wrong-package","version":"1.0"}')
  with self.assertRaisesRegex(u.Refused,'registered package identity'):self.planner.plan(self.item(target))
  outside=self.root/'outside.json';outside.write_text('{"name":"corepack"}');(peer/'package.json').unlink();(peer/'package.json').symlink_to(outside)
  with self.assertRaisesRegex(u.Refused,'ownership boundary'):self.planner.plan(self.item(target))
 def test_linked_peer_dependencies_and_staleness_still_enforced(self):
  target=self.package(self.prefix/'lib',name='demo',global_scope=True);peer,manifest=self.linked_corepack_fixture({'demo':'1.0'})
  with self.assertRaisesRegex(u.Refused,'Another installed npm'):self.planner.plan(self.item(target))
  manifest.write_text('{"name":"corepack","version":"1.0"}');plan=self.planner.plan(self.item(target))
  manifest.write_text('{"name":"corepack","version":"1.0","new":"changed"}');runner=Mock()
  with self.assertRaises(u.Refused):self.planner.execute(plan,'manager',plan['token'],runner=runner)
  runner.assert_not_called()
 def test_confirmed_npm_action_with_linked_peers_executes_only_own_manager(self):
  target=self.package(self.prefix/'lib',name='demo',global_scope=True);peer,manifest=self.linked_corepack_fixture();plan=self.planner.plan(self.item(target))
  def mocked_npm(argv,cwd,env):
   self.assertEqual(argv[:3],[str(self.node),str(self.npm),'uninstall']);self.assertEqual(argv[-2:],['--','demo']);self.assertEqual(cwd,str(self.prefix))
   self.assertIn('--global',argv);self.assertEqual(argv[argv.index('--prefix')+1],str(self.prefix))
   shutil.rmtree(target);return SimpleNamespace(returncode=0,output='MOCK npm uninstall completed')
  result=self.planner.execute(plan,'manager',plan['token'],runner=mocked_npm)
  self.assertTrue(result['success']);self.assertTrue(manifest.exists());self.assertTrue((peer/'package.json').exists())

if __name__=='__main__':unittest.main()

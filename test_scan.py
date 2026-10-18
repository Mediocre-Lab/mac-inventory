import importlib.util, json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('scan',Path(__file__).with_name('scan.py'))
scan=importlib.util.module_from_spec(spec);spec.loader.exec_module(scan)

class ScannerTests(unittest.TestCase):
 def setUp(self): scan.items.clear();scan.seen.clear();scan.warnings.clear();scan.coverage.clear()
 def test_empty_prefix(self):
  with tempfile.TemporaryDirectory() as t: scan.homebrew(Path(t));scan.npm(Path(t))
  self.assertEqual(scan.items,[])
 def test_dependency_and_direct_classification(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t)
   for name,direct in [('direct',True),('dependency',False)]:
    p=root/'Cellar'/name/'1.0';p.mkdir(parents=True)
    (p/'INSTALL_RECEIPT.json').write_text(json.dumps({'installed_on_request':direct}))
    if direct: (p/'bin').mkdir();(p/'bin/tool').write_text('never execute')
   scan.homebrew(root)
   self.assertEqual({x['name']:x['kind'] for x in scan.items},{'direct':'CLI / tool','dependency':'Dependency'})
 def test_npm_does_not_execute_hooks_or_traverse_dependencies(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'top';p.mkdir()
   (p/'package.json').write_text(json.dumps({'name':'top','version':'1.2','bin':{'top':'cli.js'},'scripts':{'postinstall':'touch SHOULD_NOT_EXIST'}}))
   nested=p/'node_modules/hidden';nested.mkdir(parents=True)
   (nested/'package.json').write_text('{"name":"hidden"}')
   scan.npm(Path(t))
   self.assertEqual([x['name'] for x in scan.items],['top'])
   self.assertFalse((p/'SHOULD_NOT_EXIST').exists())
 def test_malformed_metadata_is_visible_warning(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'broken.json';p.write_text('{invalid')
   self.assertEqual(scan.read_json(p),{})
   self.assertEqual(len(scan.warnings),1)
 def test_project_and_quantdinger_exclusion(self):
  old=scan.HOME
  with tempfile.TemporaryDirectory() as t:
   try:
    scan.HOME=Path(t)
    for name in ['cloned','QuantDinger']:
     p=scan.HOME/'Documents'/name;p.mkdir(parents=True);(p/'.git').mkdir()
     (p/'package.json').write_text('{}')
    scan.projects()
    self.assertEqual([x['name'] for x in scan.items],['cloned'])
    self.assertEqual(scan.items[0]['kind'],'Repository / project')
   finally: scan.HOME=old
 def test_deep_packages_and_no_symlink_loop(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);p=root/'a/b/c/d/node_modules/tool';p.mkdir(parents=True)
   (p/'package.json').write_text('{"name":"tool","version":"2.0"}')
   (root/'loop').symlink_to(root,target_is_directory=True)
   cache=root/'.cache';cache.mkdir();(cache/'package.json').write_text('{"name":"cached-only"}')
   scan.deep_scan([root])
   self.assertIn('tool',[x['name'] for x in scan.items])
   self.assertNotIn('cached-only',[x['name'] for x in scan.items])
   self.assertEqual(next(x for x in scan.items if x['name']=='tool')['kind'],'Dependency')
   self.assertEqual(sum(x['kind']=='Cache' for x in scan.items),1)
 def test_real_target_deduplicates_alias(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'tool';p.write_text('no execution');alias=Path(t)/'alias';alias.symlink_to(p)
   scan.add('tool','1','CLI / tool','fixture',p)
   scan.add('tool','1','CLI / tool','fixture',alias)
   self.assertEqual(len(scan.items),1);self.assertEqual(scan.items[0]['aliases'],[str(alias)])
 def test_denied_path_is_explicit_and_scan_continues(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);bad=root/'denied';bad.mkdir();good=root/'good';good.mkdir()
   (good/'package.json').write_text('{"name":"good"}')
   original=scan.os.scandir
   def read(p):
    if Path(p)==bad:raise PermissionError(13,'denied',str(bad))
    return original(p)
   with patch.object(scan.os,'scandir',side_effect=read):scan.deep_scan([root])
   self.assertTrue(any(str(bad) in w for w in scan.warnings))
   self.assertIn('good',[x['name'] for x in scan.items])
 def test_python_distribution_console_entry_point(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'env/lib/python3.12/site-packages/tool-1.dist-info';p.mkdir(parents=True)
   (p/'METADATA').write_text('Name: tool\nVersion: 1.0\n')
   (p/'entry_points.txt').write_text('[console_scripts]\ntool = module:main\n')
   (p/'REQUESTED').touch();scan.deep_scan([Path(t)])
   self.assertEqual(scan.items[0]['kind'],'CLI / tool')
   self.assertEqual(scan.items[0]['version'],'1.0')
 def test_backups_and_active_task_are_excluded(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t)
   for name in ['2026-10-10.previous','QuantDinger']:
    p=root/name;p.mkdir();(p/'package.json').write_text('{"name":"not-installed"}')
   scan.deep_scan([root])
   self.assertNotIn('not-installed',[x['name'] for x in scan.items])
   self.assertEqual(sum(x['kind']=='Backup' for x in scan.items),1)
   self.assertTrue(any('QuantDinger' in x for x in scan.coverage))
 def test_command_aliases_deduplicate_by_target(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);p=root/'tool';p.write_text('never execute');p.chmod(0o755)
   bin=root/'bin';bin.mkdir();(bin/'alias').symlink_to(p)
   scan.deep_scan([root])
   candidates=[x for x in scan.items if x['kind']=='Executable candidate']
   self.assertEqual(len(candidates),1);self.assertEqual(len(candidates[0]['aliases']),1)
 def test_bundled_app_and_archived_contents_are_not_direct_apps(self):
  scan.add('Helper','1','App','Discovered app bundle',Path('/Applications/Main.app/Contents/Helper.app'))
  scan.add('Old helper','1','App','Discovered app bundle',Path('/Applications/Old.backup.app/Contents/Helper.app'))
  scan.classify_records()
  self.assertEqual([x['kind'] for x in scan.items],['Bundled app','Backup'])
  once=json.dumps(scan.items);scan.classify_records();self.assertEqual(json.dumps(scan.items),once)

 def test_malformed_npm_fields_do_not_abort_inventory(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t)/'lib/node_modules';root.mkdir(parents=True)
   for name,metadata in [('bad-name',{'name':123,'bin':'cli.js'}),('bad-bin',{'name':'bad-bin','bin':{'bad':123}}),('good',{'name':'good','bin':'cli.js'})]:
    p=root/name;p.mkdir();(p/'package.json').write_text(json.dumps(metadata))
   scan.npm(root)
   self.assertEqual({x['name'] for x in scan.items},{'bad-name','bad-bin','good'})
   self.assertEqual(next(x for x in scan.items if x['name']=='bad-bin')['kind'],'Library')
   self.assertTrue(any('Invalid npm' in w for w in scan.warnings))
   scan.items.clear();scan.seen.clear();scan.deep_scan([root])
   self.assertIn('good',[x['name'] for x in scan.items])
 def test_malformed_app_metadata_continues_and_is_not_installed(self):
  import plistlib
  with tempfile.TemporaryDirectory() as t:
   root=Path(t)
   for name,value in [('Bad.app',['array']),('Good.app',{'CFBundleVersion':'1'})]:
    p=root/name/'Contents';p.mkdir(parents=True);(p/'Info.plist').write_bytes(plistlib.dumps(value))
   scan.deep_scan([root]);scan.classify_records()
   self.assertEqual({x['name']:x['kind'] for x in scan.items},{'Bad':'Unclassified','Good':'App'})
   self.assertTrue(any('Bad.app' in w for w in scan.warnings))
 def test_initial_application_pass_marks_unreadable_bundle_unclassified(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'Bad.app';p.mkdir()
   scan.add('Bad',None,'App','App bundle',p)
   scan.warnings.append('App metadata unreadable: '+str(p)+' (ValueError)')
   scan.classify_records()
   self.assertEqual(scan.items[0]['kind'],'Unclassified')

 def test_fifo_metadata_is_skipped_without_opening(self):
  import os
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);metadata=root/'INSTALL_RECEIPT.json';os.mkfifo(metadata)
   self.assertEqual(scan.read_json(metadata),{})
   app=root/'Bad.app';(app/'Contents').mkdir(parents=True)
   os.mkfifo(app/'Contents/Info.plist')
   self.assertEqual(scan.read_app_metadata(app),{})
   self.assertTrue(any('Non-regular metadata' in w for w in scan.warnings))

 def test_descriptor_reader_rejects_replacement_fifo_and_symlink(self):
  import os
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);p=root/'metadata';p.write_text('{}');outside=root/'outside';outside.write_text('secret')
   real_open=scan.os.open
   for mode in ('fifo','symlink'):
    if p.exists() or p.is_symlink():p.unlink()
    p.write_text('{}')
    def replace(path,flags):
     p.unlink()
     if mode=='fifo':os.mkfifo(p)
     else:p.symlink_to(outside)
     return real_open(path,flags)
    with patch.object(scan.os,'open',side_effect=replace):
     self.assertEqual(scan.read_json(p),{})
   p.unlink();p.write_bytes(b'x'*33)
   with self.assertRaises(ValueError):scan.read_metadata(p,32)
   p.write_text('safe')
   self.assertEqual(scan.metadata_text(p,32),'safe')
 def test_auxiliary_metadata_fifo_and_symlink_do_not_block(self):
  import os
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);env=root/'env';env.mkdir();os.mkfifo(env/'pyvenv.cfg')
   scan.python_env(env,'fixture')
   dist=root/'bad.dist-info';dist.mkdir();os.mkfifo(dist/'METADATA')
   scan.python_distribution(dist)
   (dist/'METADATA').unlink();(dist/'METADATA').write_text('Name: safe\nVersion: 1\n')
   target=root/'entries';target.write_text('[console_scripts]\nevil = m:f\n')
   (dist/'entry_points.txt').symlink_to(target)
   scan.python_distribution(dist)
   self.assertEqual(scan.items[-1]['launch'],'Python package; no console entry points declared')
   self.assertTrue(any('Entry-point metadata unreadable' in w for w in scan.warnings))

 def test_recovery_capsule_is_remnant_and_contents_are_excluded(self):
  import stat,plistlib
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);capsule=root/('.mac-inventory-removal-'+'a'*32);capsule.mkdir()
   app=capsule/'target/Recovered.app/Contents';app.mkdir(parents=True)
   (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion':'1'}))
   package=capsule/'target/node_modules/recovered';package.mkdir(parents=True)
   (package/'package.json').write_text('{"name":"recovered","bin":"cli.js"}')
   info=capsule.stat()
   marker={'originalPath':str(root/'Original.app'),'method':'permanent','confirmedRoot':[info.st_dev,123,stat.S_IFDIR],'capsule':[info.st_dev,info.st_ino,stat.S_IFDIR],'state':'Captured or pending; contents may be partially deleted after interruption'}
   (capsule/'recovery.json').write_text(json.dumps(marker))
   scan.deep_scan([root])
   self.assertEqual([(x['name'],x['kind']) for x in scan.items],[('Original.app','Remnant')])
   self.assertIn('Potentially partial',scan.items[0]['status'])
   self.assertTrue(any(str(capsule) in w and 'recovery' in w for w in scan.warnings))
 def test_malformed_recovery_marker_never_crashes_or_reads_original_path(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);capsule=root/('.mac-inventory-removal-'+'b'*32);capsule.mkdir()
   (capsule/'recovery.json').write_text('{"originalPath":"/never/read/this","confirmedRoot":null}')
   scan.deep_scan([root])
   self.assertEqual(scan.items,[])
   self.assertTrue(any('Invalid recovery marker' in w for w in scan.warnings))

if __name__=='__main__': unittest.main()

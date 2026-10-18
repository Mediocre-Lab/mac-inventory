"""POSIX-denial fixtures only; never request TCC access or read personal files."""
import importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path

def load(name):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class PermissionTests(unittest.TestCase):
 def setUp(self):
  if os.geteuid()==0:self.skipTest('Requires an unprivileged process to exercise POSIX permission denial')
 def test_actual_denied_subtree_continues_without_reading_package(self):
  scan=load('scan')
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);denied=root/'denied';denied.mkdir();good=root/'good';good.mkdir()
   (denied/'package.json').write_text('{"name":"must-not-read"}')
   (good/'package.json').write_text('{"name":"readable-fixture"}')
   denied.chmod(0)
   try:
    with self.assertRaises(PermissionError):list(denied.iterdir())
    scan.deep_scan([root])
    self.assertNotIn('must-not-read',[i['name'] for i in scan.items])
    self.assertIn('readable-fixture',[i['name'] for i in scan.items])
    self.assertTrue(any(str(denied) in w and 'PermissionError' in w for w in scan.warnings))
   finally:denied.chmod(0o700)
 def test_actual_unreadable_metadata_is_not_silently_accepted(self):
  scan=load('scan');removal=load('uninstall')
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'ownership.json';original=b'{"name":"fixture"}';p.write_bytes(original);p.chmod(0)
   try:
    with self.assertRaises(PermissionError):p.read_bytes()
    self.assertEqual(scan.read_json(p),{})
    self.assertTrue(any('PermissionError' in w for w in scan.warnings))
    with self.assertRaises(PermissionError):removal.metadata(p)
   finally:p.chmod(0o600)
   self.assertEqual(p.read_bytes(),original)
 def test_production_swift_snapshot_permission_denial_and_retry(self):
  source=Path(__file__).with_name('InventoryViewer.swift').read_text().split('struct ContentView: View',1)[0]
  harness=r'''
@main struct PermissionHarness {
 @MainActor static func idle(_ inventory:Inventory) async throws {
  for _ in 0..<300 { if !inventory.busy {return};try await Task.sleep(nanoseconds:20_000_000) }
  inventory.cancel();fatalError("Fixture timed out")
 }
 @MainActor static func main() async throws {
  let fm=FileManager.default, root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try fm.createDirectory(at:root,withIntermediateDirectories:true)
  defer {try? fm.removeItem(at:root)}
  let cache=root.appendingPathComponent("cache.json"),legacy=root.appendingPathComponent("legacy.json"),script=root.appendingPathComponent("scan.py")
  let old=Report(scannedAt:"old",items:[],warnings:[],coverage:[],limitations:[])
  let fresh=Report(scannedAt:"fresh",items:[],warnings:["fixture permission denial"],coverage:[],limitations:[])
  let oldData=try JSONEncoder().encode(old), freshData=try JSONEncoder().encode(fresh)
  try oldData.write(to:cache);try oldData.write(to:legacy)
  precondition(Darwin.chmod(cache.path,0)==0)
  defer {_ = Darwin.chmod(cache.path,0o600)}
  do {_ = try Inventory.readSnapshot(cache);fatalError("Unreadable snapshot accepted")}
  catch {let e=error as NSError;precondition(e.domain==NSPOSIXErrorDomain && e.code==Int(EACCES))}
  try ("import sys\nsys.stdout.write("+String(reflecting:String(data:freshData,encoding:.utf8)!)+")\n").write(to:script,atomically:true,encoding:.utf8)
  let model=Inventory(snapshotURL:cache,legacySnapshotURL:legacy,scannerURL:script)
  await model.loadOrScan();try await idle(model)
  precondition(model.report?.scannedAt=="fresh","Unreadable existing cache must refresh, not load stale legacy")
  let locked=root.appendingPathComponent("locked");try fm.createDirectory(at:locked,withIntermediateDirectories:true)
  let blocked=locked.appendingPathComponent("cache.json");try oldData.write(to:blocked)
  precondition(Darwin.chmod(locked.path,0o500)==0)
  defer {_ = Darwin.chmod(locked.path,0o700)}
  let cannotSave=Inventory(snapshotURL:blocked,legacySnapshotURL:legacy,scannerURL:script)
  cannotSave.acceptScanResult(.success(fresh),cancelled:false)
  precondition(cannotSave.report?.scannedAt=="fresh" && cannotSave.error?.contains("could not be saved")==true)
  precondition((try? Data(contentsOf:blocked))==oldData,"Denied save must preserve previous bytes")
  precondition(Darwin.chmod(locked.path,0o700)==0)
  cannotSave.acceptScanResult(.success(fresh),cancelled:false)
  precondition(cannotSave.error==nil && (try? Inventory.readSnapshot(blocked))?.scannedAt=="fresh","Retry after fixture permission restoration")
  print("PASS: actual EACCES snapshot; fresh scan over unreadable cache; denied atomic save retains displayed results and previous bytes; retry")
 }
}
'''
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);swift=root/'Permission.swift';binary=root/'permission-tests';swift.write_text(source+harness)
   subprocess.run(['xcrun','swiftc','-parse-as-library',str(swift),'-o',str(binary),'-framework','SwiftUI','-framework','AppKit','-module-cache-path',str(root/'module-cache')],check=True)
   result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30,check=True)
   self.assertIn('PASS:',result.stdout);print(result.stdout.strip())
if __name__=='__main__':unittest.main()

"""Exercise production Swift snapshot handling with synthetic data; never scan or uninstall."""
import subprocess, tempfile, unittest
from pathlib import Path

HARNESS = r''' 
@main struct SnapshotTests {
    @MainActor static func main() async throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        let cache = root.appendingPathComponent("support/current.json")
        let legacy = root.appendingPathComponent("export.json")
        let old = Report(scannedAt: "old", items: [Item(id: "fixture", name: "removed-package", version: "1", kind: "CLI / tool", source: "fixture", location: "/synthetic", purpose: "test", launch: "", status: "", aliases: nil, scanIdentity: nil)], warnings: [], coverage: [], limitations: [])
        let fresh = Report(scannedAt: "fresh", items: [], warnings: [], coverage: [], limitations: [])
        let exported = try JSONEncoder().encode(old)
        try exported.write(to: legacy)
        let inventory = Inventory(snapshotURL: cache, legacySnapshotURL: legacy)
        await inventory.loadOrScan()
        precondition(inventory.report?.scannedAt == "old", "Legacy startup")
        inventory.acceptScanResult(.success(fresh), cancelled: false)
        precondition(inventory.report?.items.isEmpty == true && inventory.error == nil, "Successful refresh")
        let saved = try Data(contentsOf: cache)
        let reopened = Inventory(snapshotURL: cache, legacySnapshotURL: legacy)
        await reopened.loadOrScan()
        precondition(reopened.report?.scannedAt == "fresh" && reopened.report?.items.isEmpty == true, "Removed row must not return on reopen")
        precondition((try? Data(contentsOf: legacy)) == exported, "User export must remain unchanged")
        reopened.acceptScanResult(.failure(NSError(domain: "fixture", code: 1)), cancelled: false)
        precondition(reopened.report?.scannedAt == "fresh" && reopened.error != nil, "Failed scan retains memory")
        precondition((try? Data(contentsOf: cache)) == saved, "Failed scan retains disk")
        reopened.acceptScanResult(.success(old), cancelled: true)
        precondition(reopened.report?.scannedAt == "fresh", "Cancelled result ignored")
        precondition((try? Data(contentsOf: cache)) == saved, "Cancellation retains disk")
        let afterFailure = Inventory(snapshotURL: cache, legacySnapshotURL: legacy)
        await afterFailure.loadOrScan()
        precondition(afterFailure.report?.items.isEmpty == true, "Reopen after failure/cancellation")
        let blocked = root.appendingPathComponent("blocked")
        try exported.write(to: blocked)
        let cannotSave = Inventory(snapshotURL: blocked.appendingPathComponent("current.json"), legacySnapshotURL: legacy)
        cannotSave.report = old
        cannotSave.acceptScanResult(.success(fresh), cancelled: false)
        precondition(cannotSave.report?.scannedAt == "fresh" && cannotSave.error?.contains("could not be saved") == true, "Save failure displays fresh results with warning")
        precondition((try? Data(contentsOf: blocked)) == exported, "Save failure preserves existing data")
        print("PASS: legacy startup, refresh/reopen without removed row, export preservation, scan failure, cancellation, reopen after failure, save failure")
    }
}
'''

PROCESS_HARNESS = r'''
@main struct ProcessLifecycleTests {
    @MainActor static func waitForIdle(_ inventory: Inventory) async throws {
        for _ in 0..<300 {
            if !inventory.busy { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        inventory.cancel()
        fatalError("Synthetic scan did not finish within six seconds")
    }
    @MainActor static func main() async throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        let cache = root.appendingPathComponent("current.json")
        let legacy = root.appendingPathComponent("legacy.json")
        let script = root.appendingPathComponent("synthetic_scan.py")
        let old = Report(scannedAt: "old", items: [], warnings: [], coverage: [], limitations: [])
        let fresh = Report(scannedAt: "fresh", items: [], warnings: ["fixture"], coverage: [], limitations: [])
        let oldData = try JSONEncoder().encode(old)
        try oldData.write(to: cache)
        let inventory = Inventory(snapshotURL: cache, legacySnapshotURL: legacy, scannerURL: script)
        await inventory.loadOrScan()
        let encoded = try JSONEncoder().encode(fresh).base64EncodedString()
        let success = "import base64\nprint(base64.b64decode('\(encoded)').decode())\n"
        try success.write(to: script, atomically: true, encoding: .utf8)
        inventory.refresh()
        try await waitForIdle(inventory)
        precondition(inventory.report?.scannedAt == "fresh" && inventory.error == nil, "Actual subprocess refresh succeeds")
        let saved = try Data(contentsOf: cache)
        try "import sys\nsys.exit(4)\n".write(to: script, atomically: true, encoding: .utf8)
        inventory.refresh()
        try await waitForIdle(inventory)
        precondition(inventory.report?.scannedAt == "fresh" && inventory.error != nil, "Failed subprocess retains displayed report")
        precondition((try? Data(contentsOf: cache)) == saved, "Failure preserves automatic snapshot")
        try "print('not JSON')\n".write(to: script, atomically: true, encoding: .utf8)
        inventory.refresh()
        try await waitForIdle(inventory)
        precondition(inventory.error != nil && (try? Data(contentsOf: cache)) == saved, "Malformed subprocess output preserves snapshot")
        try "import json,sys,time\nprint(json.dumps({'progress':'fixture scanning'}),file=sys.stderr,flush=True)\ntime.sleep(30)\n".write(to: script, atomically: true, encoding: .utf8)
        inventory.refresh()
        for _ in 0..<300 {
            if inventory.progress == "fixture scanning" { break }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        precondition(inventory.busy && inventory.progress == "fixture scanning", "Production progress pipe")
        inventory.cancel()
        try await waitForIdle(inventory)
        precondition(inventory.error?.contains("cancelled") == true && (try? Data(contentsOf: cache)) == saved, "Actual cancellation retains snapshot")
        try success.write(to: script, atomically: true, encoding: .utf8)
        inventory.refresh()
        try await waitForIdle(inventory)
        precondition(inventory.error == nil && inventory.report?.scannedAt == "fresh", "Retry recovers")
        let missingRuntime = Inventory(snapshotURL: cache, legacySnapshotURL: legacy, scannerURL: script, pythonURL: root.appendingPathComponent("missing-python"))
        await missingRuntime.loadOrScan(); missingRuntime.refresh()
        precondition(!missingRuntime.busy && missingRuntime.error != nil && missingRuntime.report?.scannedAt == "fresh", "Missing runtime is visible and retains results")
        let delayed = Inventory(snapshotURL: cache, legacySnapshotURL: legacy, scannerURL: script, snapshotReader: { _ in
            Thread.sleep(forTimeInterval: 0.2); return old
        })
        let pending = Task { await delayed.loadOrScan() }
        try await Task.sleep(nanoseconds: 20_000_000)
        precondition(delayed.busy, "Pending snapshot load is visible")
        delayed.cancel()
        precondition(!delayed.busy && delayed.error?.contains("cancelled") == true, "Cancel releases UI without waiting for filesystem")
        delayed.refresh(); try await waitForIdle(delayed)
        await pending.value
        precondition(delayed.report?.scannedAt == "fresh", "Cancelled startup cannot overwrite a later refresh")
        let fifo = root.appendingPathComponent("fifo")
        precondition(Darwin.mkfifo(fifo.path, 0o600) == 0)
        do { _ = try Inventory.readSnapshot(fifo); fatalError("FIFO snapshot accepted") } catch {}
        let linked = root.appendingPathComponent("linked.json")
        try fm.createSymbolicLink(at: linked, withDestinationURL: cache)
        do { _ = try Inventory.readSnapshot(linked); fatalError("Linked snapshot accepted") } catch {}
        let response = Inventory.completedRemovalResponse(["error":"Partial; Recovery: /synthetic/capsule/target"], cancelled: true)
        precondition((response["error"] as? String)?.contains("Recovery: /synthetic/capsule/target") == true, "Cancellation preserves recovery location")
        let completed = Inventory.completedRemovalResponse(["success":true,"output":"Moved the confirmed target to /synthetic/Trash"], cancelled: true)
        precondition(completed["success"] as? Bool == true && (completed["output"] as? String)?.contains("/synthetic/Trash") == true, "Completed mutation result survives late cancellation")
        inventory.removalOutput = "Confirmed target permanently deleted through descriptor-relative traversal."
        precondition(inventory.removalTitle == "Removal completed", "Manual success is recognized")
        print("PASS: real synthetic subprocess refresh, progress, failure, malformed output, cancellation, retry, missing runtime, recovery response")
    }
}
'''

class SnapshotTests(unittest.TestCase):
    def test_production_snapshot_lifecycle(self):
        source = Path(__file__).with_name("InventoryViewer.swift").read_text()
        # Compile the actual model and persistence methods, excluding only UI views.
        model = source.split("struct ContentView: View", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            swift = root / "SnapshotTests.swift"
            swift.write_text(model + HARNESS)
            binary = root / "snapshot-tests"
            subprocess.run(["xcrun", "swiftc", "-parse-as-library", str(swift), "-o", str(binary), "-framework", "SwiftUI", "-framework", "AppKit", "-module-cache-path", str(root / "module-cache")], check=True)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            self.assertIn("PASS:", result.stdout)
            print(result.stdout.strip())

    def test_production_refresh_process_and_cancellation(self):
        source = Path(__file__).with_name("InventoryViewer.swift").read_text()
        model = source.split("struct ContentView: View", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            swift = root / "ProcessTests.swift"
            swift.write_text(model + PROCESS_HARNESS)
            binary = root / "process-tests"
            subprocess.run(["xcrun", "swiftc", "-parse-as-library", str(swift), "-o", str(binary), "-framework", "SwiftUI", "-framework", "AppKit", "-module-cache-path", str(root / "module-cache")], check=True)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=35)
            self.assertIn("PASS:", result.stdout)
            print(result.stdout.strip())

if __name__ == "__main__":
    unittest.main()

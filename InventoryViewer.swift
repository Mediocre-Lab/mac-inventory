import SwiftUI
import AppKit
import Darwin

struct Item: Codable, Identifiable {
    let id, name, version, kind, source, location, purpose, launch, status: String
    let aliases: [String]?
    let scanIdentity: String?
}
struct Report: Codable {
    let scannedAt: String
    let items: [Item]
    let warnings, coverage, limitations: [String]
}
struct RemovalPlan: Decodable {
    let action, manager, target, scope, title, consequences, token: String
    let argv: [String]
    let appTargets: [String]
    let allowPermanent: Bool
}
@MainActor final class Inventory: ObservableObject {
    @Published var query = ""
    @Published var category = "Installed"
    @Published var selection: String?
    @Published var coverageVisible = false
    @Published var report: Report?
    @Published var busy = false
    @Published var error: String?
    @Published var progress = "Starting scan…"
    @Published var removalBusy = false
    @Published var removalCancellable = false
    @Published var removalOutput = ""
    @Published var removalDetailsVisible = false
    // Automatic snapshots are separate from user-selected exports and legacy reports.
    private let snapshotURL: URL
    private let legacySnapshotURL: URL
    private let scannerURL: URL?
    private let pythonURL: URL
    private let snapshotReader: @Sendable (URL) throws -> Report
    private var loadGeneration: UUID?
    init(snapshotURL: URL? = nil, legacySnapshotURL: URL? = nil, scannerURL: URL? = nil, pythonURL: URL = URL(fileURLWithPath: "/usr/bin/python3"), snapshotReader: @escaping @Sendable (URL) throws -> Report = { try Inventory.readSnapshot($0) }) {
        self.scannerURL = scannerURL ?? Bundle.main.url(forResource: "scan", withExtension: "py")
        self.pythonURL = pythonURL
        self.snapshotReader = snapshotReader
        self.snapshotURL = snapshotURL ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Mac Inventory", isDirectory: true).appendingPathComponent("inventory-current.json")
        self.legacySnapshotURL = legacySnapshotURL ?? Bundle.main.bundleURL.deletingLastPathComponent()
            .appendingPathComponent("inventory-deep.json")
    }
    private var removalMode = "plan"
    var removalTitle: String {
        if removalBusy { return removalMode == "plan" ? "Checking package ownership…" : "Removal in progress…" }
        let text = removalOutput.lowercased()
        if text.contains("protected") { return "This item is protected" }
        if text.contains("cancelled") { return "Cancelled" }
        if text.contains("verified target is absent") || text.contains("moved the exact target") || text.contains("moved the confirmed target") || text.contains("confirmed target permanently deleted") || text.contains("completed before interruption") { return "Removal completed" }
        return "Removal needs attention"
    }
    var removalHint: String {
        if removalBusy { return removalCancellable ? "You can cancel this operation. Details shows live output." : "Finishing the confirmed operation. Details shows its output." }
        let text = removalOutput.lowercased()
        if text.contains("protected") { return "Shared runtime or manager components cannot be removed here. Select the package you want to uninstall." }
        if text.contains("preview cancelled") || text.contains("permanent deletion cancelled") { return "Nothing changed. Select an item and choose Uninstall… to review its action." }
        if text.contains("stale") || text.contains("refresh before") { return "Refresh the inventory, then select the item and preview its action again." }
        if text.contains("linked") { return "The metadata link could not be matched to a verified owner. No removal was attempted; Details explains the boundary." }
        if text.contains("another package manager") || text.contains("unsupported installer") { return "This item has a different owning manager. No replacement manager or forced deletion was selected." }
        if text.contains("requires this") || text.contains("shared") { return "Another installed package uses this item. Remove its dependents first with their owning manager." }
        if text.contains("no verified owning manager") { return "No verified manager or safely bounded fallback is available for this target. Choose another item or inspect Details." }
        return String(removalOutput.components(separatedBy: "\n").first?.prefix(200) ?? "Open Details for the operation result.")
    }
    var removalNeedsRefresh: Bool { !removalBusy && (removalOutput.lowercased().contains("stale") || removalOutput.lowercased().contains("refresh before")) }
    private var removalProcess: Process?
    private var removalCancelled = false
    private var process: Process?
    private var cancelled = false
    func cancelRemoval() {
        guard removalBusy && removalCancellable else { return }
        removalCancelled = true
        removalProcess?.terminate()
        removalOutput += "\nCancelling the owned operation. An interrupted removal may have partial effects."
    }
    func removalCall(_ mode: String, _ request: [String: Any], completion: @escaping ([String: Any]) -> Void) {
        guard !removalBusy && !busy else { removalOutput = "Wait for the active scan/operation, then preview again. Nothing changed."; return }
        guard let script = Bundle.main.url(forResource: "uninstall", withExtension: "py"),
              let input = try? JSONSerialization.data(withJSONObject: request) else {
            removalOutput = "Removal adapter is missing or request is invalid."; return
        }
        guard input.count < 1_500_000 else { removalOutput = "The ownership proof is too large for a bounded operation. Nothing changed."; return }
        let worker = Process(), output = Pipe(), diagnostics = Pipe(), stdin = Pipe()
        worker.executableURL = pythonURL
        worker.arguments = ["-I", "-B", script.path, mode]
        worker.standardOutput = output; worker.standardError = diagnostics; worker.standardInput = stdin
        removalBusy = true; removalCancellable = true; removalCancelled = false; removalProcess = worker
        removalMode = mode
        removalOutput = mode == "plan" ? "Verifying exact package ownership…" : "Executing only the confirmed action…"
        diagnostics.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            for line in text.split(separator: "\n") {
                if let data = String(line).data(using: .utf8),
                   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String],
                   let message = obj["progress"] {
                    DispatchQueue.main.async { [weak self] in
                        guard let self else { return }
                        self.removalOutput = String((self.removalOutput + "\n" + message).suffix(12000))
                    }
                }
            }
        }
        do {
            try worker.run()
            stdin.fileHandleForWriting.write(input)
            try? stdin.fileHandleForWriting.close()
        } catch {
            removalOutput = error.localizedDescription; removalBusy = false; removalCancellable = false; removalProcess = nil
            diagnostics.fileHandleForReading.readabilityHandler = nil; return
        }
        Task {
            let data = await Task.detached {
                let data = output.fileHandleForReading.readDataToEndOfFile()
                worker.waitUntilExit(); return data
            }.value
            diagnostics.fileHandleForReading.readabilityHandler = nil
            removalBusy = false; removalCancellable = false; removalProcess = nil
            let response = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            completion(Self.completedRemovalResponse(response, cancelled: removalCancelled))
        }
    }
    static func completedRemovalResponse(_ response: [String: Any]?, cancelled: Bool) -> [String: Any] {
        var result = response ?? ["error": "The removal adapter could not finish. No automatic fallback was attempted."]
        if cancelled {
            let note = "Cancellation was requested. Review the exact operation result and any recovery location below; actions may be partial. No automatic deletion fallback was attempted."
            if let error = result["error"] as? String { result["error"] = note + "\n" + error }
            else if let output = result["output"] as? String { result["output"] = note + "\n" + output }
            else { result["error"] = note }
        }
        return result
    }
    func prepareRemoval(_ item: Item) {
        guard !busy && !removalBusy else { return }
        guard let encoded = try? JSONEncoder().encode(item),
              let obj = try? JSONSerialization.jsonObject(with: encoded) else { return }
        removalCall("plan", ["item": obj]) { response in
            if let error = response["error"] as? String { self.removalOutput = error; return }
            guard let data = try? JSONSerialization.data(withJSONObject: response),
                  let plan = try? JSONDecoder().decode(RemovalPlan.self, from: data) else {
                self.removalOutput = "Invalid removal plan. Nothing changed."; return
            }
            if NSWorkspace.shared.runningApplications.contains(where: { app in
                guard let running = app.bundleURL?.resolvingSymlinksInPath().path else { return false }
                return plan.appTargets.contains { running == $0 || running.hasPrefix($0 + "/") }
            }) {
                self.removalOutput = "The selected app is running. Quit it yourself before previewing removal. Nothing changed."; return
            }
            self.previewRemoval(plan, raw: response)
        }
    }
    func previewRemoval(_ plan: RemovalPlan, raw: [String: Any]) {
        guard ["manager", "manual"].contains(plan.action) else {
            removalOutput = "Unsupported removal action. Nothing changed."; return
        }
        let alert = NSAlert()
        alert.messageText = plan.title
        let args = (try? JSONEncoder().encode(plan.argv)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        alert.informativeText = "Target: \(plan.target)\nOwning scope: \(plan.scope)\nManager: \(plan.manager)\n\n\(plan.consequences)\n\nExact argv (no shell):\n\(args)\n\nThis action is optional. Cancellation changes nothing."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: plan.action == "manager" ? "Uninstall" : "Move to Trash")
        if plan.action == "manual" && plan.allowPermanent { alert.addButton(withTitle: "Permanently delete…") }
        alert.buttons[0].keyEquivalent = "\r"; alert.buttons[1].keyEquivalent = ""
        let choice = alert.runModal()
        if choice == .alertSecondButtonReturn {
            performRemoval(plan, raw: raw, method: plan.action == "manager" ? "manager" : "trash")
        } else if choice == .alertThirdButtonReturn && plan.action == "manual" && plan.allowPermanent {
            confirmPermanent(plan, raw: raw)
        } else { removalOutput = "Preview cancelled. Nothing changed." }
    }
    func confirmPermanent(_ plan: RemovalPlan, raw: [String: Any]) {
        let phrase = "DELETE " + URL(fileURLWithPath: plan.target).lastPathComponent
        let alert = NSAlert(); alert.alertStyle = .critical
        alert.messageText = "Permanently delete this exact target?"
        alert.informativeText = "\(plan.target)\n\nThis permanently deletes the exact verified file or directory, including its contents. It cannot be recovered through Trash. Related manager records, links and user data are not cleaned. No shared runtime or project root is eligible.\n\nType exactly: \(phrase)"
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 460, height: 26))
        field.placeholderString = phrase; alert.accessoryView = field
        alert.addButton(withTitle: "Cancel"); alert.addButton(withTitle: "Permanently delete")
        alert.buttons[0].keyEquivalent = "\r"; alert.buttons[1].keyEquivalent = ""; alert.buttons[1].isEnabled = false
        let observer = NotificationCenter.default.addObserver(forName: NSControl.textDidChangeNotification, object: field, queue: .main) { _ in
            alert.buttons[1].isEnabled = field.stringValue == phrase
        }
        let choice = alert.runModal(); NotificationCenter.default.removeObserver(observer)
        if choice == .alertSecondButtonReturn && field.stringValue == phrase {
            performRemoval(plan, raw: raw, method: "permanent", typed: phrase)
        } else { removalOutput = "Permanent deletion cancelled. Nothing changed." }
    }
    func performRemoval(_ plan: RemovalPlan, raw: [String: Any], method: String, typed: String = "") {
        guard (plan.action == "manager" && method == "manager") || (plan.action == "manual" && ["trash", "permanent"].contains(method)) else {
            removalOutput = "Action does not match the confirmed plan. Nothing changed."; return
        }
        removalCall("execute", ["plan": raw, "method": method, "confirmation": plan.token, "typedConfirmation": typed]) { response in
            if let error = response["error"] as? String { self.removalOutput = error }
            else { self.removalOutput = response["output"] as? String ?? "Review the operation result." }
            self.refresh()
        }
    }
    nonisolated static func readSnapshot(_ url: URL) throws -> Report {
        let fd = Darwin.open(url.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { Darwin.close(fd) }
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0, (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG), info.st_size < 100_000_000 else {
            throw NSError(domain: "Inventory", code: 3, userInfo: [NSLocalizedDescriptionKey: "Saved inventory is not a bounded regular file."])
        }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while data.count <= 100_000_000 {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
            guard count >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            if count == 0 { return try JSONDecoder().decode(Report.self, from: data) }
            data.append(contentsOf: buffer.prefix(count))
        }
        throw NSError(domain: "Inventory", code: 3, userInfo: [NSLocalizedDescriptionKey: "Saved inventory exceeds the size limit."])
    }
    func loadOrScan() async {
        guard !busy && !removalBusy else { return }
        busy = true; cancelled = false; progress = "Loading saved inventory…"
        let generation = UUID(); loadGeneration = generation
        let cache = snapshotURL, legacy = legacySnapshotURL, reader = snapshotReader
        let saved = await Task.detached { () -> Report? in
            // Only an absent cache permits legacy fallback. No extended attributes
            // are needed, and all filesystem reads/decoding stay off the UI actor.
            var info = stat()
            let status = Darwin.lstat(cache.path, &info)
            let chosen = status == 0 || errno != ENOENT ? cache : legacy
            return try? reader(chosen)
        }.value
        guard loadGeneration == generation else { return }
        loadGeneration = nil; busy = false
        if cancelled {
            error = report == nil ? "Loading cancelled. Refresh to try again." : "Loading cancelled. Previous results were retained."
        } else if let saved { report = saved }
        else { refresh() }
    }
    func acceptScanResult(_ result: Result<Report, Error>, cancelled: Bool) {
        guard !cancelled else {
            error = report == nil ? "Scan cancelled. Refresh to try again." : "Scan cancelled. Previous results were retained."
            return
        }
        switch result {
        case .success(let fresh):
            report = fresh
            do {
                let data = try JSONEncoder().encode(fresh)
                try FileManager.default.createDirectory(at: snapshotURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                try data.write(to: snapshotURL, options: .atomic)
                error = nil
            } catch {
                self.error = "Fresh results are displayed, but could not be saved for reopening: " + error.localizedDescription
            }
        case .failure(let failure): self.error = failure.localizedDescription
        }
    }
    func exportReport() {
        guard let report else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "inventory-deep.json"
        panel.directoryURL = Bundle.main.bundleURL.deletingLastPathComponent()
        panel.canCreateDirectories = true
        if panel.runModal() == .OK, let url = panel.url {
            do {
                let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                try encoder.encode(report).write(to: url, options: .atomic)
            } catch { self.error = "Export failed: " + error.localizedDescription }
        }
    }
    func cancel() {
        guard busy else { return }
        cancelled = true
        if loadGeneration != nil {
            loadGeneration = nil; busy = false
            error = report == nil ? "Loading cancelled. Refresh to try again." : "Loading cancelled. Previous results were retained."
            return
        }
        if process?.isRunning == true { process?.terminate() }
        progress = "Cancelling…"
    }
    func refresh() {
        guard !busy && !removalBusy else { return }
        busy = true; error = nil; cancelled = false; progress = "Starting deep metadata scan…"
        guard let script = scannerURL else {
            error = "Scanner resource is missing. Rebuild the app."; busy = false; return
        }
        let worker = Process(), output = Pipe(), diagnostics = Pipe()
        worker.executableURL = pythonURL
        worker.arguments = ["-I", "-B", script.path]
        worker.standardOutput = output; worker.standardError = diagnostics
        process = worker
        diagnostics.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            for line in text.split(separator: "\n") {
                if let data = String(line).data(using: .utf8),
                   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String],
                   let message = obj["progress"] {
                    DispatchQueue.main.async { [weak self] in self?.progress = message }
                }
            }
        }
        do { try worker.run() }
        catch { self.error = error.localizedDescription; busy = false; process = nil; diagnostics.fileHandleForReading.readabilityHandler = nil; return }
        Task {
            let result: Result<Report, Error> = await Task.detached {
                do {
                    let data = output.fileHandleForReading.readDataToEndOfFile()
                    worker.waitUntilExit()
                    guard worker.terminationStatus == 0 else { throw NSError(domain: "Inventory", code: 2, userInfo: [NSLocalizedDescriptionKey: "The scanner could not finish. Check folder access and try Refresh."]) }
                    return .success(try JSONDecoder().decode(Report.self, from: data))
                } catch { return .failure(error) }
            }.value
            diagnostics.fileHandleForReading.readabilityHandler = nil
            acceptScanResult(result, cancelled: cancelled)
            process = nil; busy = false
        }
    }

}

struct ContentView: View {
    @StateObject private var inventory = Inventory()
    private let categories = ["Installed", "App", "Apple app", "Bundled app", "CLI / tool", "Runtime", "Library", "Environment", "Dependency", "Repository / project", "Package record", "Backup", "Remnant", "Unclassified", "Executable candidate", "Apple tool", "Cache", "All"]
    private var filtered: [Item] {
        (inventory.report?.items ?? []).filter { item in
            let accepted = inventory.category == "All" || (inventory.category == "Installed" ? ["App", "CLI / tool", "Runtime", "Library"].contains(item.kind) : inventory.category == item.kind)
            return accepted && (inventory.query.isEmpty || [item.name, item.source, item.location, item.purpose, item.version].joined(separator: " ").localizedCaseInsensitiveContains(inventory.query))
        }
    }
    private var selected: Item? { filtered.first { $0.id == inventory.selection } }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: "desktopcomputer").font(.largeTitle).foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Mac Inventory").font(.title2.bold())
                    Text("Deep inventory · apps, tools, dependencies and executable candidates").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Export JSON") { inventory.exportReport() }.disabled(inventory.report == nil || inventory.removalBusy)
                Button { inventory.coverageVisible = true } label: { Label("Coverage", systemImage: "info.circle") }
                if inventory.busy { Button("Cancel") { inventory.cancel() } }
                if inventory.removalBusy && inventory.removalCancellable { Button("Cancel operation") { inventory.cancelRemoval() } }
                Button { inventory.refresh() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .disabled(inventory.busy || inventory.removalBusy).keyboardShortcut("r", modifiers: .command)
            }.padding(20)
            HStack {
                TextField("Search name, purpose, version or location", text: $inventory.query).textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("inventorySearch")
                Picker("Show", selection: $inventory.category) { ForEach(categories, id: \.self) { Text($0).tag($0) } }
                    .frame(width: 250)
            }.padding(.horizontal, 20).padding(.bottom, 12)
            if !inventory.removalOutput.isEmpty {
                HStack(spacing: 12) {
                    Image(systemName: inventory.removalBusy ? "hourglass" : "info.circle").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(inventory.removalTitle).font(.callout.weight(.semibold))
                        Text(inventory.removalHint).font(.callout).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 12)
                    if inventory.removalNeedsRefresh { Button("Refresh") { inventory.removalOutput = ""; inventory.refresh() }.disabled(inventory.busy) }
                    Button("Details…") { inventory.removalDetailsVisible = true }
                    if !inventory.removalBusy { Button { inventory.removalOutput = "" } label: { Image(systemName: "xmark") }.buttonStyle(.plain).help("Dismiss status").accessibilityLabel("Dismiss status") }
                }.padding(.horizontal, 20).padding(.vertical, 10).fixedSize(horizontal: false, vertical: true)
                    .background(Color(nsColor: .controlBackgroundColor))
            }
            if let error = inventory.error {
                HStack { Image(systemName: "exclamationmark.triangle"); Text(error); Spacer(); Button("Retry") { inventory.refresh() } }
                    .padding(12).background(Color.orange.opacity(0.12))
            }
            Divider()
            HSplitView {
                VStack(spacing: 0) {
                    if inventory.busy && inventory.report == nil {
                        Spacer(); ProgressView(inventory.progress); Spacer()
                    } else if filtered.isEmpty {
                        Spacer()
                        Image(systemName: "magnifyingglass").font(.largeTitle).foregroundStyle(.secondary)
                        Text(inventory.report == nil ? "No scan results yet" : "No matching items").font(.headline).padding(.top, 8)
                        Text("Try another search or category, or Refresh.").foregroundStyle(.secondary)
                        Spacer()
                    } else {
                        List(selection: $inventory.selection) {
                            ForEach(filtered) { item in
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: icon(item.kind)).foregroundStyle(.blue).frame(width: 24).padding(.top, 3)
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack { Text(item.name).font(.headline); Spacer(); Text(item.version).foregroundStyle(.secondary) }
                                        Text(item.purpose).lineLimit(1).foregroundStyle(.secondary)
                                        Text("\(item.kind) · \(item.source)").font(.caption).foregroundStyle(.secondary)
                                    }
                                }.padding(.vertical, 5).tag(item.id)
                            }
                        }.listStyle(.inset)
                    }
                }.frame(minWidth: 420)
                ScrollView {
                    if let item = selected {
                        VStack(alignment: .leading, spacing: 18) {
                            Image(systemName: icon(item.kind)).font(.system(size: 36)).foregroundStyle(.blue)
                            Text(item.name).font(.title.bold())
                            Text(item.purpose).font(.title3)
                            Button("Uninstall…") { inventory.prepareRemoval(item) }
                                .disabled(inventory.busy || inventory.removalBusy)
                                .help("Review the exact owning-manager action before confirming. Nothing changes during preview.")
                            Text("Review and confirm before anything changes.").font(.caption).foregroundStyle(.secondary)
                            field("Version", item.version)
                            field("Category / source", "\(item.kind) · \(item.source)")
                            field("Evidence", item.status)
                            field("Location", item.location)
                            if let aliases = item.aliases, !aliases.isEmpty { field("Other locations / aliases", aliases.joined(separator: "\n")) }
                            field("How to open or use", item.launch.isEmpty ? "No launch instructions available" : item.launch)
                            HStack {
                                Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.location)]) }
                                Button("Copy location") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(item.location, forType: .string) }
                            }
                            Text("Scanning is read-only. Removal requires a verified preview and your explicit confirmation.").font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(24)
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "sidebar.right").font(.largeTitle).foregroundStyle(.secondary)
                            Text("Select an item").font(.headline)
                            Text("See its version, location and opening instructions.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                        }.frame(maxWidth: .infinity).padding(40)
                    }
                }.frame(minWidth: 300, idealWidth: 360).id(selected?.id)
            }
            Divider()
            HStack {
                if inventory.busy { ProgressView().controlSize(.small); Text(inventory.progress) }
                else { Text("\(filtered.count) shown · \(inventory.report?.items.count ?? 0) records") }
                Spacer()
                Text(inventory.report.map { "Scanned \($0.scannedAt)" } ?? "Read-only local scan").foregroundStyle(.secondary)
            }.font(.caption).padding(12)
        }.frame(minWidth: 900, minHeight: 560)
        .task { await inventory.loadOrScan() }
        .onChange(of: inventory.selection) { _ in if !inventory.removalBusy { inventory.removalOutput = "" } }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in inventory.cancel(); inventory.cancelRemoval() }
        .sheet(isPresented: $inventory.removalDetailsVisible) {
            VStack(alignment: .leading, spacing: 16) {
                Text("Removal details").font(.title2.bold())
                Text(inventory.removalTitle).foregroundStyle(.secondary)
                ScrollView { Text(inventory.removalOutput).font(.system(.body, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(12).accessibilityElement(children: .ignore).accessibilityLabel(inventory.removalOutput) }
                    .background(Color(nsColor: .textBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 8))
                HStack { Spacer(); Button("Done") { inventory.removalDetailsVisible = false }.keyboardShortcut(.defaultAction) }
            }.padding(24).frame(width: 720, height: 440)
        }
        .sheet(isPresented: $inventory.coverageVisible) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Scan coverage & limitations").font(.title2.bold())
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Deep, read-only metadata scan. Permission and identification limits prevent guaranteed completeness.").font(.headline)
                        ForEach(inventory.report?.limitations ?? [], id: \.self) { Text("• " + $0) }
                        Text("Inspected locations").font(.headline).padding(.top)
                        ForEach(inventory.report?.coverage ?? [], id: \.self) { Text($0).font(.system(.caption, design: .monospaced)) }
                        Text("Scan warnings (\(inventory.report?.warnings.count ?? 0))").font(.headline).padding(.top)
                        ForEach(inventory.report?.warnings ?? [], id: \.self) { Text($0).font(.caption) }
                        if inventory.report?.warnings.isEmpty == true { Text("No metadata read errors in the inspected locations.") }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityElement(children: .contain)
                }
                HStack { Spacer(); Button("Done") { inventory.coverageVisible = false }.keyboardShortcut(.defaultAction) }
            }.padding(24).frame(width: 680, height: 540)
        }
    }
    func field(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title.uppercased()).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
    func icon(_ kind: String) -> String {
        switch kind {
        case "App", "Apple app": return "app"
        case "Repository / project": return "folder"
        case "Dependency", "Library": return "shippingbox"
        case "Runtime", "Environment": return "gearshape.2"
        case "Remnant", "Backup": return "archivebox"
        default: return "terminal"
        }
    }
}

@main struct InventoryViewerApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
            .defaultSize(width: 1120, height: 740)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}

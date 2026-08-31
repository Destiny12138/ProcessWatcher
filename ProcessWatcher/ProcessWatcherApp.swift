import SwiftUI
import Cocoa
import UserNotifications
import CoreWLAN
import Network

// MARK: - 1. 配置
let BLACKLIST: [String] = [
    "zerotier", "tailscale", "ngrok", "frpc", "frps",
    "npc", "nps", "clash", "v2ray", "trojan",
    "gost", "brook", "mtunnel", "proxifier", "openvpn",
    "v2rayu", "mihomo", "verge"
]

let LOG_PATH = NSHomeDirectory() + "/Library/Logs/ProcessMonitor.log"
let MAX_LOG_SIZE: UInt64 = 1_000_000  // 1MB，后续可能记录更多内容，够用
let MAX_LOG_LINES = 20_000            // 行数兜底上限，主要按大小限制

var alertCache: [String: TimeInterval] = [:]
let alertCacheLock = NSLock()

// MARK: - 2. 核心扫描函数
func scanProcesses() {
    var pids = [pid_t](repeating: 0, count: 4096)
    let bytesReturned = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
    let actualCount = Int(bytesReturned) / MemoryLayout<pid_t>.stride
    
    var foundProcesses: [String] = []
    
    for i in 0..<actualCount {
        let pid = pids[i]
        guard pid > 0 else { continue }
        
        var nameBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let nameLen = proc_name(pid, &nameBuffer, UInt32(nameBuffer.count))
        
        if nameLen > 0 {
            let processName = String(cString: nameBuffer).lowercased()
            for keyword in BLACKLIST {
                if processName.contains(keyword) {
                    var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                    let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
                    let fullPath = pathLen > 0 ? String(cString: pathBuffer) : "未知路径"
                    
                    let logEntry = "[\(Date())] ⚠️ 发现可疑进程: \(processName) (PID: \(pid), 路径: \(fullPath))"
                    foundProcesses.append(logEntry)
                    break
                }
            }
        }
    }
    
    if !foundProcesses.isEmpty {
        for entry in foundProcesses {
            logToFile(entry)
            sendNotification(message: entry)
        }
    }
}

// MARK: - 3. 日志记录（带大小限制）
func logToFile(_ message: String) {
    let logDir = (LOG_PATH as NSString).deletingLastPathComponent
    try? FileManager.default.createDirectory(atPath: logDir, withIntermediateDirectories: true)
    
    // 追加写入
    if let fileHandle = FileHandle(forWritingAtPath: LOG_PATH) {
        fileHandle.seekToEndOfFile()
        if let data = (message + "\n").data(using: .utf8) {
            fileHandle.write(data)
        }
        fileHandle.closeFile()
    } else {
        try? (message + "\n").write(toFile: LOG_PATH, atomically: true, encoding: .utf8)
    }
    
    // 检查文件大小，超过限制则截断
    truncateLogIfNeeded()
}

func truncateLogIfNeeded() {
    guard let attributes = try? FileManager.default.attributesOfItem(atPath: LOG_PATH),
          let fileSize = attributes[.size] as? UInt64,
          fileSize > MAX_LOG_SIZE else { return }
    
    // 读取文件内容，按行分割
    guard let content = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) else { return }
    var lines = content.components(separatedBy: .newlines)
    if lines.last?.isEmpty == true { lines.removeLast() }
    
    // 从最新往前保留，保证写入内容不超过大小上限（不做时间限制）
    var kept: [String] = []
    var byteCount = 0
    for line in lines.reversed() {
        let lineBytes = line.utf8.count + 1
        if kept.count >= MAX_LOG_LINES || byteCount + lineBytes > Int(MAX_LOG_SIZE) {
            break
        }
        kept.append(line)
        byteCount += lineBytes
    }
    
    let newContent = kept.reversed().joined(separator: "\n")
    
    try? newContent.write(toFile: LOG_PATH, atomically: true, encoding: .utf8)
}

// MARK: - 4. 系统通知
func sendNotification(message: String) {
    guard let pidRange = message.range(of: "PID: \\d+", options: .regularExpression) else { return }
    let key = String(message[pidRange])
    let now = Date().timeIntervalSince1970

    alertCacheLock.lock()
    if let last = alertCache[key], (now - last) < 300 {
        alertCacheLock.unlock()
        return
    }
    alertCache[key] = now
    alertCacheLock.unlock()

    let content = UNMutableNotificationContent()
    content.title = "🚨 内网穿透进程监控"
    content.body = message.components(separatedBy: "⚠️").last?.trimmingCharacters(in: .whitespaces) ?? message
    content.sound = .default
    if #available(macOS 12.0, *) {
        content.interruptionLevel = .timeSensitive
    }
    
    let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
}

/// 通用通知（非进程告警，例如 WiFi 连接提醒），无需 PID、不按进程去重
func sendSimpleNotification(title: String, body: String) {
    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    content.sound = .default
    if #available(macOS 12.0, *) {
        content.interruptionLevel = .timeSensitive
    }
    let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
}

// MARK: - 5. WiFi 监听（NWPathMonitor 触发器，非轮询，无需位置权限）
class WiFiMonitor: NSObject {
    static let companySSID = "H6886"

    private let wifiClient = CWWiFiClient.shared()
    private var pathMonitor: NWPathMonitor?
    private var monitorQueue: DispatchQueue?
    private var lastSSID: String?

    /// WiFi 状态变化回调（ssid, 上次是否公司WiFi, 当前是否公司WiFi）
    var onWiFiChange: ((_ ssid: String?, _ wasCompany: Bool, _ isCompany: Bool) -> Void)?

    func start() {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "process.watcher.wifi", qos: .utility)
        monitorQueue = queue
        monitor.pathUpdateHandler = { [weak self] _ in
            self?.handleWiFiChange()
        }
        pathMonitor = monitor
        monitor.start(queue: queue)

        // 启动时主动读取一次当前状态
        handleWiFiChange()
    }

    func stop() {
        pathMonitor?.cancel()
        pathMonitor = nil
        monitorQueue = nil
    }

    func handleWiFiChange() {
        let ssid = currentSSID()
        let wasCompany = lastSSID?.caseInsensitiveCompare(Self.companySSID) == .orderedSame
        let isCompany = ssid?.caseInsensitiveCompare(Self.companySSID) == .orderedSame
        lastSSID = ssid
        DispatchQueue.main.async { [weak self] in
            self?.onWiFiChange?(ssid, wasCompany, isCompany)
        }
    }

    private func currentSSID() -> String? {
        // 优先用系统命令读取当前WiFi（不需要位置权限）
        if let ssid = networksetupSSID(), !ssid.isEmpty {
            return ssid
        }
        // 兜底：CoreWLAN（通常需要位置授权，未授权时返回 nil）
        if let ssid = wifiClient.interface()?.ssid(), !ssid.isEmpty {
            return ssid
        }
        return nil
    }

    private func networksetupSSID() -> String? {
        guard let interfaceName = wifiClient.interface()?.interfaceName else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-getairportnetwork", interfaceName]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if output.isEmpty || output.lowercased().contains("not associated") {
                return nil
            }
            // 输出形如 "Current Wi-Fi Network: H6886"，取冒号后内容
            if let range = output.range(of: ": ") {
                let name = String(output[range.upperBound...]).trimmingCharacters(in: .whitespaces)
                return name.isEmpty ? nil : name
            }
            return output
        } catch {
            return nil
        }
    }
}

// MARK: - 6. AppDelegate
class AppDelegate: NSObject, NSApplicationDelegate, ObservableObject {
    @Published var isPaused = false
    @Published var isOnCompanyWiFi = false
    var timer: DispatchSourceTimer?
    var logWindowController: NSWindowController?
    let wifiMonitor = WiFiMonitor()
    private var lastLoggedSSID: String?

    func applicationWillFinishLaunching(_ notification: Notification) {
        // 纯菜单栏应用：不在 Dock 显示
        NSApp.setActivationPolicy(.accessory)
    }

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // 请求通知权限
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        
        // WiFi 监听：连上公司WiFi自动开启监控（接入状态变化用 NWPathMonitor 推送，无需位置权限）
        wifiMonitor.onWiFiChange = { [weak self] ssid, wasCompany, isCompany in
            guard let self = self else { return }
            self.handleWiFiChange(ssid: ssid, wasCompany: wasCompany, isCompany: isCompany)
        }
        wifiMonitor.start()
        
        // 启动定时器（定时器会在立即触发一次并随后每 10 秒扫描）
        startScanTimer()
    }

    func handleWiFiChange(ssid: String?, wasCompany: Bool, isCompany: Bool) {
        isOnCompanyWiFi = isCompany
        if ssid != lastLoggedSSID {
            lastLoggedSSID = ssid
            logToFile("[\(Date())] 📶 当前WiFi: \(ssid ?? "无")")
        }
        if isCompany && !wasCompany {
            logToFile("[\(Date())] 📶 已连接公司 WiFi (\(WiFiMonitor.companySSID))，监控已自动开启")
            sendSimpleNotification(title: "🏢 已连接公司WiFi", body: "已连接到 \(WiFiMonitor.companySSID)，监控已自动开启")
            if isPaused {
                setPaused(false)
            }
        } else if !isCompany && wasCompany {
            logToFile("[\(Date())] 📶 已断开公司 WiFi (\(WiFiMonitor.companySSID))")
        }
    }

    func setPaused(_ paused: Bool) {
        guard isPaused != paused else { return }
        isPaused = paused
        if isPaused {
            timer?.suspend()
        } else {
            timer?.resume()
        }
    }

    func showLogWindow() {
        // 窗口已存在时直接前置显示，保留其自动刷新状态
        if let windowController = logWindowController, let window = windowController.window {
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            return
        }
        
        // 创建 SwiftUI 视图作为日志显示
        let logView = LogView()
        let hostingController = NSHostingController(rootView: logView)
        let window = NSWindow(contentViewController: hostingController)
        window.title = "进程监控日志"
        window.setContentSize(NSSize(width: 600, height: 400))
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.isReleasedWhenClosed = false  // 关闭时只隐藏，不销毁
        
        let windowController = NSWindowController(window: window)
        self.logWindowController = windowController
        NSApp.activate(ignoringOtherApps: true)
        windowController.showWindow(nil)
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
    }

    func quitApp() {
        NSApp.terminate(nil)
    }

    func applicationWillTerminate(_ notification: Notification) {
        // 若定时器处于挂起状态，先恢复再取消，避免清理不彻底
        if isPaused {
            timer?.resume()
        }
        timer?.cancel()
    }

    func startScanTimer() {
        // 串行队列，避免多次扫描并发导致共享状态竞争
        let queue = DispatchQueue(label: "process.watcher.scan", qos: .background)
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer?.schedule(deadline: .now(), repeating: .seconds(10), leeway: .seconds(5))
        timer?.setEventHandler { [weak self] in
            guard let self = self, !self.isPaused else { return }
            scanProcesses()
        }
        timer?.resume()
    }
}

// MARK: - 7. SwiftUI 日志显示视图
struct LogView: View {
    @State private var content: String = "日志为空"
    @State private var autoRefresh: Bool = true
    private let refreshTimer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("进程监控日志")
                    .font(.headline)
                Spacer()
                Toggle("自动刷新", isOn: $autoRefresh)
                    .toggleStyle(.checkbox)
                Button("刷新") {
                    reloadLog()
                }
                .help("立即重新读取日志")
                Button("清理日志") {
                    clearLog()
                }
                .help("删除全部日志")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            Divider()

            ScrollView {
                Text(content.isEmpty ? "日志为空" : content)
                    .font(.system(.body, design: .monospaced))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
        }
        .frame(minWidth: 520, minHeight: 400)
        .onAppear {
            reloadLog()
        }
        .onReceive(refreshTimer) { _ in
            if autoRefresh {
                reloadLog()
            }
        }
    }

    private func reloadLog() {
        if let text = try? String(contentsOfFile: LOG_PATH, encoding: .utf8), !text.isEmpty {
            content = text
        } else {
            content = "日志为空"
        }
    }

    private func clearLog() {
        try? "".write(toFile: LOG_PATH, atomically: true, encoding: .utf8)
        content = "日志为空"
    }
}

// MARK: - 8. 菜单栏视图
struct MenuBarView: View {
    @ObservedObject var delegate: AppDelegate
    
    var body: some View {
        Button(delegate.isOnCompanyWiFi ? "🟢 已连接公司WiFi (\(WiFiMonitor.companySSID))" : "⚪ 未连接公司WiFi") {
        }
        .disabled(true)
        Divider()
        Button("📋 查看日志") {
            DispatchQueue.main.async {
                delegate.showLogWindow()
            }
        }
        Button(delegate.isPaused ? "▶️ 恢复监控" : "⏸️ 暂停监控") {
            delegate.setPaused(!delegate.isPaused)
        }
        Divider()
        Button("退出") {
            DispatchQueue.main.async {
                delegate.quitApp()
            }
        }
        .keyboardShortcut("q")
    }
}

// MARK: - 9. App 入口（菜单栏应用，不在 Dock 显示）
@main
struct ProcessWatcherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    
    var body: some Scene {
        MenuBarExtra {
            MenuBarView(delegate: delegate)
        } label: {
            Text("🛡️")
        }
        .menuBarExtraStyle(.menu)
    }
}

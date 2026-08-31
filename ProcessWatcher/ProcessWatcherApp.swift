import SwiftUI
import Cocoa
import UserNotifications

// MARK: - 1. 配置
let BLACKLIST: [String] = [
    "zerotier", "tailscale", "ngrok", "frpc", "frps",
    "npc", "nps", "clash", "v2ray", "trojan",
    "gost", "brook", "mtunnel", "proxifier", "openvpn"
]

let LOG_PATH = NSHomeDirectory() + "/Library/Logs/ProcessMonitor.log"
let MAX_LOG_SIZE: UInt64 = 1_000_000  // 1MB
let MAX_LOG_LINES = 1000              // 保留最近1000行

var alertCache: [String: TimeInterval] = [:]

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
    let lines = content.components(separatedBy: .newlines)
    
    // 保留最后 MAX_LOG_LINES 行
    let keepLines = lines.suffix(MAX_LOG_LINES)
    let newContent = keepLines.joined(separator: "\n")
    
    try? newContent.write(toFile: LOG_PATH, atomically: true, encoding: .utf8)
}

// MARK: - 4. 系统通知
func sendNotification(message: String) {
    guard let pidRange = message.range(of: "PID: \\d+", options: .regularExpression) else { return }
    let key = String(message[pidRange])
    let now = Date().timeIntervalSince1970
    
    if let last = alertCache[key], (now - last) < 300 {
        return
    }
    alertCache[key] = now
    
    let content = UNMutableNotificationContent()
    content.title = "🚨 内网穿透进程监控"
    content.body = message.components(separatedBy: "⚠️").last?.trimmingCharacters(in: .whitespaces) ?? message
    content.sound = .default
    
    let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
}

// MARK: - 5. AppDelegate
class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem?
    var timer: DispatchSourceTimer?
    var isPaused = false
    var logWindowController: NSWindowController?

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // 请求通知权限
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        
        // 创建菜单栏图标
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem?.button {
            button.title = "🛡️"
            button.font = NSFont.systemFont(ofSize: 14)
        }
        
        // 构建菜单
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "📋 查看日志", action: #selector(showLogWindow), keyEquivalent: "l"))
        menu.addItem(NSMenuItem.separator())
        let toggleItem = NSMenuItem(title: "⏸️ 暂停监控", action: #selector(togglePause), keyEquivalent: "s")
        toggleItem.state = .off
        menu.addItem(toggleItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "退出", action: #selector(quitApp), keyEquivalent: "q"))
        statusItem?.menu = menu
        
        // 启动定时器
        startScanTimer()
        scanProcesses()
    }
    
    @objc func togglePause(sender: NSMenuItem) {
        isPaused.toggle()
        sender.title = isPaused ? "▶️ 恢复监控" : "⏸️ 暂停监控"
        if isPaused {
            timer?.suspend()
        } else {
            timer?.resume()
        }
    }
    
    @objc func showLogWindow() {
        // 如果窗口已存在，则前置显示
        if let windowController = logWindowController, let window = windowController.window, window.isVisible {
            window.makeKeyAndOrderFront(nil)
            return
        }
        
        // 读取日志内容
        let logContent: String
        if let content = try? String(contentsOfFile: LOG_PATH, encoding: .utf8), !content.isEmpty {
            logContent = content
        } else {
            logContent = "日志为空"
        }
        
        // 创建 SwiftUI 视图作为日志显示
        let logView = LogView(content: logContent)
        let hostingController = NSHostingController(rootView: logView)
        let window = NSWindow(contentViewController: hostingController)
        window.title = "进程监控日志"
        window.setContentSize(NSSize(width: 600, height: 400))
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.isReleasedWhenClosed = false  // 关闭时只隐藏，不销毁
        
        let windowController = NSWindowController(window: window)
        self.logWindowController = windowController
        windowController.showWindow(nil)
    }
    
    @objc func quitApp() {
        timer?.cancel()
        NSApplication.shared.terminate(nil)
    }
    
    func startScanTimer() {
        let queue = DispatchQueue.global(qos: .background)
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer?.schedule(deadline: .now(), repeating: .seconds(60), leeway: .seconds(10))
        timer?.setEventHandler { [weak self] in
            guard let self = self, !self.isPaused else { return }
            scanProcesses()
        }
        timer?.resume()
    }
}

// MARK: - 6. SwiftUI 日志显示视图
struct LogView: View {
    let content: String
    
    var body: some View {
        ScrollView {
            Text(content)
                .font(.system(.body, design: .monospaced))
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 400, minHeight: 300)
    }
}

// MARK: - 7. App 入口
@main
struct ProcessWatcherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    
    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

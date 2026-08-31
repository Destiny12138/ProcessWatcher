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
let MAX_LOG_SIZE: UInt64 = 100_000    // 100KB，日志量不大，足够追溯近期记录
let MAX_LOG_LINES = 2000              // 行数兜底上限，主要按大小限制

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
    static var shared: AppDelegate?

    override init() {
        super.init()
        Self.shared = self
    }

    var timer: DispatchSourceTimer?
    var isPaused = false
    var logWindowController: NSWindowController?

    func applicationWillFinishLaunching(_ notification: Notification) {
        // 纯菜单栏应用：不在 Dock 显示
        NSApp.setActivationPolicy(.accessory)
    }

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // 请求通知权限
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        
        // 启动定时器
        startScanTimer()
        
        // 首次扫描放到后台队列，避免阻塞主线程
        DispatchQueue.global(qos: .background).async {
            scanProcesses()
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
        // 读取日志内容，空日志也照常弹出
        let logContent: String
        if let content = try? String(contentsOfFile: LOG_PATH, encoding: .utf8), !content.isEmpty {
            logContent = content
        } else {
            logContent = "日志为空"
        }

        // 窗口已存在时复用并刷新内容，不重复创建
        if let windowController = logWindowController, let window = windowController.window {
            if let hostingController = window.contentViewController as? NSHostingController<LogView> {
                hostingController.rootView = LogView(content: logContent)
            }
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            return
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

// MARK: - 7. 菜单栏视图
struct MenuBarView: View {
    private var delegate: AppDelegate? {
        AppDelegate.shared ?? NSApp.delegate as? AppDelegate
    }
    
    var body: some View {
        Button("📋 查看日志") {
            DispatchQueue.main.async {
                delegate?.showLogWindow()
            }
        }
        Button(delegate?.isPaused == true ? "▶️ 恢复监控" : "⏸️ 暂停监控") {
            guard let delegate else { return }
            delegate.setPaused(!delegate.isPaused)
        }
        Divider()
        Button("退出") {
            DispatchQueue.main.async {
                delegate?.quitApp()
            }
        }
        .keyboardShortcut("q")
    }
}

// MARK: - 8. App 入口（菜单栏应用，不在 Dock 显示）
@main
struct ProcessWatcherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    
    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
        } label: {
            Text("🛡️")
        }
        .menuBarExtraStyle(.menu)
    }
}

// watchdog_core.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

namespace WatchdogCore {

    struct WatchEvent {
        DWORD64 timestamp;
        DWORD type;
        std::wstring description;
        bool handled;
    };

    struct GuardedProcess {
        DWORD pid;
        std::wstring name;
        DWORD64 startTime;
        DWORD restartCount;
        bool alive;
    };

    class ProcessWatchdog {
    private:
        std::vector<GuardedProcess> m_processes;
        std::vector<WatchEvent> m_events;
        std::mutex m_mutex;
        std::thread m_watchdogThread;
        bool m_running;

        void WatchdogLoop() {
            while (m_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5000));

                std::lock_guard<std::mutex> lock(m_mutex);
                for (auto& proc : m_processes) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.pid);
                    if (hProcess) {
                        DWORD exitCode = 0;
                        GetExitCodeProcess(hProcess, &exitCode);
                        if (exitCode != STILL_ACTIVE) {
                            proc.alive = false;
                            proc.restartCount++;
                            RestartProcess(proc);
                        }
                        CloseHandle(hProcess);
                    } else {
                        proc.alive = false;
                        proc.restartCount++;
                        RestartProcess(proc);
                    }
                }
            }
        }

        void RestartProcess(GuardedProcess& proc) {
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = { 0 };
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            if (CreateProcessW(proc.name.c_str(), NULL, NULL, NULL, FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                proc.pid = pi.dwProcessId;
                proc.alive = true;
                proc.startTime = GetTickCount64();
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }

    public:
        ProcessWatchdog() : m_running(false) {}

        void Start() {
            m_running = true;
            m_watchdogThread = std::thread(&ProcessWatchdog::WatchdogLoop, this);
        }

        void Stop() {
            m_running = false;
            if (m_watchdogThread.joinable())
                m_watchdogThread.join();
        }

        void AddProcess(DWORD pid, const std::wstring& name) {
            std::lock_guard<std::mutex> lock(m_mutex);
            GuardedProcess proc = { pid, name, GetTickCount64(), 0, true };
            m_processes.push_back(proc);
        }

        void RemoveProcess(DWORD pid) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_processes.erase(
                std::remove_if(m_processes.begin(), m_processes.end(),
                    [pid](const GuardedProcess& p) { return p.pid == pid; }),
                m_processes.end()
            );
        }

        DWORD GetRestartCount(DWORD pid) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& proc : m_processes) {
                if (proc.pid == pid) return proc.restartCount;
            }
            return 0;
        }
    };

    class HeartbeatMonitor {
    private:
        DWORD64 m_lastHeartbeat;
        DWORD m_timeout;
        bool m_alive;

    public:
        HeartbeatMonitor() : m_lastHeartbeat(0), m_timeout(30000), m_alive(true) {}

        void Beat() {
            m_lastHeartbeat = GetTickCount64();
            m_alive = true;
        }

        bool Check() {
            if (GetTickCount64() - m_lastHeartbeat > m_timeout) {
                m_alive = false;
                return false;
            }
            return true;
        }

        bool IsAlive() { return m_alive; }
        void SetTimeout(DWORD ms) { m_timeout = ms; }
    };

    class CrashHandler {
    private:
        static CrashHandler* g_instance;
        LPTOP_LEVEL_EXCEPTION_FILTER m_oldFilter;

        static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo) {
            DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
            LPVOID address = ExceptionInfo->ExceptionRecord->ExceptionAddress;

            // Log crash info
            WCHAR buf[256];
            swprintf_s(buf, L"Crash: code=0x%08X addr=%p", code, address);
            OutputDebugStringW(buf);

            // Restart on critical crashes
            if (code == EXCEPTION_ACCESS_VIOLATION ||
                code == EXCEPTION_STACK_OVERFLOW ||
                code == EXCEPTION_ILLEGAL_INSTRUCTION) {
                // Trigger restart
                ExitProcess(1);
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

    public:
        CrashHandler() : m_oldFilter(NULL) {}

        void Install() {
            m_oldFilter = SetUnhandledExceptionFilter(ExceptionFilter);
        }

        void Uninstall() {
            if (m_oldFilter)
                SetUnhandledExceptionFilter(m_oldFilter);
        }
    };

    class DeadlockDetector {
    private:
        std::vector<DWORD> m_threadIds;
        std::map<DWORD, DWORD64> m_lastActivity;
        std::mutex m_mutex;
        DWORD m_deadlockThreshold;

    public:
        DeadlockDetector() : m_deadlockThreshold(60000) {}

        void RegisterThread(DWORD tid) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_threadIds.push_back(tid);
            m_lastActivity[tid] = GetTickCount64();
        }

        void UpdateActivity(DWORD tid) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastActivity[tid] = GetTickCount64();
        }

        bool DetectDeadlock() {
            std::lock_guard<std::mutex> lock(m_mutex);
            DWORD64 now = GetTickCount64();

            for (DWORD tid : m_threadIds) {
                if (now - m_lastActivity[tid] > m_deadlockThreshold) {
                    return true;
                }
            }
            return false;
        }
    };

    ProcessWatchdog g_watchdog;
    HeartbeatMonitor g_heartbeat;
    CrashHandler g_crashHandler;
    DeadlockDetector g_deadlockDetector;

    void InitializeWatchdog() {
        g_crashHandler.Install();
        g_watchdog.Start();
        g_heartbeat.Beat();
    }

    void ShutdownWatchdog() {
        g_watchdog.Stop();
        g_crashHandler.Uninstall();
    }
}

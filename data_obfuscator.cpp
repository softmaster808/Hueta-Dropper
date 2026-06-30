// data_obfuscator.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <random>

namespace DataObfuscator {

    struct ObfuscatedString {
        std::vector<BYTE> data;
        BYTE key;
        DWORD checksum;
        bool encrypted;
    };

    struct PolymorphicBlock {
        std::vector<BYTE> code;
        DWORD entryOffset;
        DWORD size;
        DWORD seed;
    };

    class StringEncryptor {
    private:
        std::map<DWORD, ObfuscatedString> m_strings;
        DWORD m_counter;
        std::mt19937 m_rng;

        BYTE GenerateKey() {
            std::uniform_int_distribution<BYTE> dist(1, 255);
            return dist(m_rng);
        }

        DWORD CalculateChecksum(const std::vector<BYTE>& data) {
            DWORD checksum = 0xFFFFFFFF;
            for (BYTE b : data) {
                checksum ^= b;
                checksum = (checksum >> 1) | (checksum << 31);
            }
            return checksum;
        }

    public:
        StringEncryptor() : m_counter(0) {
            m_rng.seed(GetTickCount() ^ GetCurrentProcessId());
        }

        DWORD StoreString(const std::wstring& str) {
            BYTE key = GenerateKey();
            std::vector<BYTE> data;
            const BYTE* raw = (const BYTE*)str.c_str();
            size_t len = (str.length() + 1) * sizeof(wchar_t);

            for (size_t i = 0; i < len; i++)
                data.push_back(raw[i] ^ key);

            DWORD checksum = CalculateChecksum(data);

            ObfuscatedString obs = { data, key, checksum, true };
            m_strings[m_counter] = obs;
            return m_counter++;
        }

        std::wstring RetrieveString(DWORD id) {
            auto it = m_strings.find(id);
            if (it == m_strings.end()) return L"";

            ObfuscatedString& obs = it->second;
            std::vector<BYTE> decrypted = obs.data;

            for (size_t i = 0; i < decrypted.size(); i++)
                decrypted[i] ^= obs.key;

            DWORD checksum = CalculateChecksum(obs.data);
            if (checksum != obs.checksum) return L"[TAMPERED]";

            return std::wstring((wchar_t*)decrypted.data());
        }

        void Wipe(DWORD id) {
            auto it = m_strings.find(id);
            if (it != m_strings.end()) {
                SecureZeroMemory(it->second.data.data(), it->second.data.size());
                m_strings.erase(it);
            }
        }
    };

    class PolymorphicEngine {
    private:
        std::mt19937 m_rng;

        std::vector<BYTE> GenerateJunkBytes(DWORD count) {
            std::vector<BYTE> junk;
            std::uniform_int_distribution<BYTE> dist(0, 255);
            for (DWORD i = 0; i < count; i++)
                junk.push_back(dist(m_rng));
            return junk;
        }

        std::vector<BYTE> GenerateNopEquivalent() {
            std::vector<BYTE> nops;
            std::uniform_int_distribution<int> choice(0, 4);

            switch (choice(m_rng)) {
                case 0: nops = { 0x90 }; break;                           // NOP
                case 1: nops = { 0x66, 0x90 }; break;                    // XCHG AX, AX
                case 2: nops = { 0x48, 0x87, 0xC0 }; break;             // XCHG RAX, RAX
                case 3: nops = { 0x48, 0x8B, 0xC0 }; break;             // MOV RAX, RAX
                case 4: nops = { 0x50, 0x58 }; break;                    // PUSH RAX; POP RAX
            }
            return nops;
        }

    public:
        PolymorphicEngine() {
            m_rng.seed(GetTickCount64() ^ GetCurrentThreadId());
        }

        PolymorphicBlock GenerateBlock(const std::vector<BYTE>& originalCode) {
            PolymorphicBlock block;
            block.size = originalCode.size() + 256;
            block.seed = (DWORD)m_rng();

            // Insert junk
            std::vector<BYTE> junkBefore = GenerateJunkBytes(32);
            block.code.insert(block.code.end(), junkBefore.begin(), junkBefore.end());

            // Insert NOP equivalents randomly in original code
            for (size_t i = 0; i < originalCode.size(); i++) {
                if (i % 8 == 0) {
                    std::vector<BYTE> nopEq = GenerateNopEquivalent();
                    block.code.insert(block.code.end(), nopEq.begin(), nopEq.end());
                }
                block.code.push_back(originalCode[i]);
            }

            // Insert junk after
            std::vector<BYTE> junkAfter = GenerateJunkBytes(32);
            block.code.insert(block.code.end(), junkAfter.begin(), junkAfter.end());

            block.entryOffset = (DWORD)junkBefore.size();
            return block;
        }
    };

    class IntegrityChecker {
    private:
        std::map<LPVOID, DWORD> m_checkpoints;
        std::mutex m_mutex;

    public:
        void AddCheckpoint(LPVOID addr, SIZE_T size) {
            std::lock_guard<std::mutex> lock(m_mutex);
            DWORD checksum = 0;
            BYTE* p = (BYTE*)addr;
            for (SIZE_T i = 0; i < size; i++)
                checksum = (checksum << 3) ^ p[i];
            m_checkpoints[addr] = checksum;
        }

        bool VerifyCheckpoint(LPVOID addr, SIZE_T size) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_checkpoints.find(addr);
            if (it == m_checkpoints.end()) return false;

            DWORD checksum = 0;
            BYTE* p = (BYTE*)addr;
            for (SIZE_T i = 0; i < size; i++)
                checksum = (checksum << 3) ^ p[i];

            return checksum == it->second;
        }
    };

    class AntiDump {
    private:
        bool m_protected;

    public:
        AntiDump() : m_protected(false) {}

        bool ProtectPEHeader() {
            HMODULE hModule = GetModuleHandle(NULL);
            BYTE* base = (BYTE*)hModule;
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

            DWORD oldProtect;
            if (VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &oldProtect)) {
                // Wipe DOS header
                SecureZeroMemory(dos, sizeof(IMAGE_DOS_HEADER));
                // Wipe NT headers
                SecureZeroMemory(nt, sizeof(IMAGE_NT_HEADERS));

                VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, oldProtect, &oldProtect);
                m_protected = true;
                return true;
            }
            return false;
        }

        bool ErasePEHeader() {
            return ProtectPEHeader();
        }
    };

    StringEncryptor g_stringEncryptor;
    PolymorphicEngine g_polymorphicEngine;
    IntegrityChecker g_integrityChecker;
    AntiDump g_antiDump;

    void InitializeObfuscation() {
        g_antiDump.ErasePEHeader();
    }
}

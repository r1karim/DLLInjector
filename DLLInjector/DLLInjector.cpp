// DLLInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

DWORD GetProcId(const char* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);
            
        if (Process32First(hSnap,&processEntry)) {
            do {
                if (!_stricmp(processEntry.szExeFile,procName)) {
                    procId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &processEntry));
        }

    }
    CloseHandle(hSnap);
    return procId;
}

int main()
{
    const char* dllPath = "C:\\Userrs\\adri711\desktop\\file.dll";
    const char* procName = "csgo.exe";
    DWORD procId = GetProcId(procName);
   
    if (!procId) abort();
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        void* loc = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(hProcess, loc, dllPath, strlen(dllPath) + 1, 0);
        HANDLE hThread = CreateRemoteThread(hProcess,0,0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
        
        if (hThread) {
            CloseHandle(hThread);
        }
    }

    if (hProcess) {
        CloseHandle(hProcess);
    }

    return 0;
}

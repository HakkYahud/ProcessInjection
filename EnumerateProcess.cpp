// ProcessInjection.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <TlHelp32.h>

int main(int argc, char* argv[])
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe; // PROCESSENTRY32 is a structure that that describe the info of a process when a snapshot is taken, can get PPID (th32ParentProcessID), PID(th32ProcessID), Pname(szExeFile) etc.
    PROCESSENTRY32 targetPE;
    BOOL targetFound = FALSE;
    std::string targetProcessName = "explorer.exe";
    std::wstring wTargetProcessName(targetProcessName.begin(), targetProcessName.end());
    printf("Search for %ls\n", wTargetProcessName.c_str());
    // HANDLE CreateToolhelp32Snapshot(DWORD SnapshotInfo, DWORD processID)
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // SNAPPROCESS includes all processes in the system in the snapshot, 0 for processID indicates the current process
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Error to get a handle of snapshot");
        return -1;
    }
    pe.dwSize = sizeof(PROCESSENTRY32);
    printf("[+] List Process\n");
    do {
        std::wstring currentProcessName(pe.szExeFile); // Must convert wchar to wstring to compare string
        printf("Process ID: %lu, Process Name: %ls\n", pe.th32ProcessID, currentProcessName.c_str()); // In Windows, DWORD are unsigned long => %lu
        if (wTargetProcessName.compare(currentProcessName) == 0) {
            targetFound = TRUE;
            targetPE = pe;
        }
    } while (Process32Next(hSnapshot, &pe));
    
    printf("\n");

    if (targetFound == TRUE) {
        printf("[+] Process has been found\n");
        printf("Process ID: %lu, Process Name: %ls\n", targetPE.th32ProcessID, targetPE.szExeFile);
    }
    
    printf("\n");
    
    printf("Press any key to quit");
    getchar();
    
    return 0;
}

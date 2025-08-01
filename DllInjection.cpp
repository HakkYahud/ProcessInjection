#include <iostream>
#include <string>
#include <windows.h>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>

using namespace std;
int main(int argc, char* argv[]){
    HANDLE hSnapshot;
    HANDLE hProcess = GetCurrentProcess();
    TCHAR szExeFileName[MAX_PATH];

    GetModuleFileName(NULL, szExeFileName, MAX_PATH);
    wstring wFileName(szExeFileName);
    string fileName(wFileName.begin(), wFileName.end());
    cout << "Current File Name : " + fileName << endl;


    PROCESSENTRY32 pe;
    PROCESSENTRY32 targetPE;
    BOOL targetFound = FALSE;
    std::string targetProcessName = argv[1];
    LPCSTR DllPath = argv[2]; // The Path to our DLL
    cout << "Starting injection" << endl;
    std::wstring wTargetProcessName(targetProcessName.begin(), targetProcessName.end());
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "[-] Error to get a handle on the process snapshot", "Process Snapshot 404", 0);
        return 0;
    }

    else {
        pe.dwSize = sizeof(PROCESSENTRY32);
        printf("[+] List Process\n");
        do {
            std::wstring currentProcessName(pe.szExeFile);
            printf("Process ID: %lu, Process Name: %ls\n", pe.th32ProcessID, currentProcessName.c_str());
            if (wTargetProcessName.compare(currentProcessName) == 0) {
                printf("[+] Found Process\n");
                targetFound = TRUE;
                targetPE = pe;
                printf("Process ID: %lu, Process Name: %ls\n", targetPE.th32ProcessID, targetPE.szExeFile);
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    if (targetFound == TRUE){
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPE.th32ProcessID); // Opening the Process with All Access
        // Allocate memory for the dllpath in the target process, length of the path string + null terminator
        LPVOID pDllPath = VirtualAllocEx(handle, 0, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        // Write the path to the address of the memory we just allocated in the target process
        WriteProcessMemory(handle, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, 0);
        // Create a Remote Thread in the target process which calls LoadLibraryA as our dllpath as an argument -> program loads our dll
        HANDLE hLoadThread = CreateRemoteThread(handle, 0, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), pDllPath, 0, 0);
        WaitForSingleObject(hLoadThread, INFINITE); // Wait for the execution of our loader thread to finish
        CloseHandle(handle);
    }
    else {
        printf("[!] Process not found");
    }

    return 0;
}
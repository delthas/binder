#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <psapi.h>

int hookDLL(char *dll_path, const PROCESS_INFORMATION *pi) {
  HMODULE hKernel32 = GetModuleHandle("Kernel32");
  LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryA");
  
  void *dll_addr = VirtualAllocEx(pi->hProcess, 0, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(pi->hProcess, dll_addr, dll_path, strlen(dll_path) + 1, 0);
  
  HANDLE hThread = CreateRemoteThread(pi->hProcess, 0, 0, pLoadLibrary, dll_addr, 0, 0);
  
  if (!hThread) {
    printf("Could not create remote thread [%d]\n", (int) GetLastError());
    VirtualFreeEx(pi->hProcess, dll_addr, 0, MEM_RELEASE);
    TerminateProcess(pi->hProcess, 1);
    return 6;
  }
  
  DWORD hookedDLL;
  WaitForSingleObject(hThread, INFINITE);
  if(!GetExitCodeThread(hThread, &hookedDLL)) {
    printf("Exit code failed with [%d]\n", (int) GetLastError());
    return 7;
  }
  CloseHandle(hThread);
  
  VirtualFreeEx(pi->hProcess, dll_addr, 0, MEM_RELEASE);
  
  if (!hookedDLL) {
    printf("Remote thread exited without handle\n");
    TerminateProcess(pi->hProcess, 1);
    return 8;
  }
  
  return 0;
}

int hook(char *dll_path, char *exe_path, char **args, int argv) {
  // Initialize process
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  WIN32_FILE_ATTRIBUTE_DATA exe_info, dat_info;
  
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  
  if (!GetFileAttributesEx(exe_path, GetFileExInfoStandard, &exe_info)) {
    printf("Couldn't find exe='%s'\nError [%d]\n", exe_path, (int) GetLastError());
    return 3;
  }
  
  if (!GetFileAttributesEx(dll_path, GetFileExInfoStandard, &dat_info)) {
    printf("Couldn't find dll='%s'\nError [%d]\n", dll_path, (int) GetLastError());
    return 4;
  }
  
  int length = (int) (strlen(exe_path) + 3 + argv);
  for (int i = 0; i < argv; ++i) {
    length += strlen(args[i]);
  }
  char command[strlen(exe_path) + 3];
  int offset = 0;
  command[offset] = '\"';
  ++offset;
  strcpy(&command[offset], exe_path);
  offset += strlen(exe_path);
  command[offset] = '\"';
  ++offset;
  for (int i = 0; i < argv; ++i) {
    command[offset] = ' ';
    ++offset;
    strcpy(&command[offset], args[i]);
    offset += strlen(args[i]);
  }
  command[offset] = '\0';
  
  char dir[strlen(exe_path) + 1];
  _splitpath_s(exe_path, NULL, 0, dir, sizeof(dir), NULL, 0, NULL, 0);
  
  if (!CreateProcessA(0, command, 0, 0, TRUE, CREATE_SUSPENDED, 0, dir, &si, &pi)) {
    printf("exe='%s'\ndir='%s'\nCould not create process [%d]\n", exe_path, dir, (int) GetLastError());
    return 5;
  }
  
  int res = hookDLL(dll_path, &pi);
  if (res) {
    return res;
  }
  ResumeThread(pi.hThread);
  
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Syntax: <dll_path> <exe_path> [exe_arg1 [...]]\n");
    return 1;
  }
  
  return hook(argv[1], argv[2], &argv[3], argc - 3);
}

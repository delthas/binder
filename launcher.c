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
    printf("Could not create remote thread [%d].", (int) GetLastError());
    VirtualFreeEx(pi->hProcess, dll_addr, 0, MEM_RELEASE);
    TerminateProcess(pi->hProcess, 1);
    return 6;
  }
  
  DWORD hookedDLL;
  WaitForSingleObject(hThread, INFINITE);
  GetExitCodeThread(hThread, &hookedDLL);
  CloseHandle(hThread);
  
  VirtualFreeEx(pi->hProcess, dll_addr, 0, MEM_RELEASE);
  
  if (!hookedDLL) {
    printf("Remote thread exited with [%d].", (int) GetLastError());
    TerminateProcess(pi->hProcess, 1);
    return 7;
  }
  
  return 0;
}

int getBase(HANDLE hnd, void **address, WORD *orig_code) {
  char imageName[MAX_PATH + 1];
  DWORD len = GetProcessImageFileNameA(hnd, imageName, sizeof(imageName));
  if(!len) {
    printf("Could not get process image file name [%d].", (int) GetLastError());
    return 9;
  }
  imageName[len] = '\0';
  
  HMODULE hMods[1024];
  DWORD cbNeeded;
  MODULEINFO modInfo;
  if (EnumProcessModules(hnd, hMods, sizeof(hMods), &cbNeeded)) {
    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      TCHAR szModName[MAX_PATH];
      if (GetModuleFileNameEx(hnd, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
        if(!strcmp(imageName, szModName)) {
          continue;
        }
        if(!GetModuleInformation(hnd, hMods[i], &modInfo, sizeof(modInfo))) {
          printf("Could not get module information [%d].", (int) GetLastError());
          return 10;
        }
        *address = modInfo.EntryPoint;
        ReadProcessMemory(hnd, modInfo.EntryPoint, orig_code, 2, 0);
        return 0;
      }
    }
  }
  printf("Could not find executable module [%d].", (int) GetLastError());
  return 11;
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
    printf("Couldn't find exe='%s'\nError [%d].", exe_path, (int) GetLastError());
    return 3;
  }
  
  if (!GetFileAttributesEx(dll_path, GetFileExInfoStandard, &dat_info)) {
    printf("Couldn't find dll='%s'\nError [%d].", dll_path, (int) GetLastError());
    return 4;
  }
  
  int length = strlen(exe_path) + 3 + argv;
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
    printf("exe='%s'\ndir='%s'\nCould not create process [%d].", exe_path, dir, (int) GetLastError());
    return 5;
  }
  
  // Wait for process startup, block
  WORD lock_code = 0xFEEB;
  WORD orig_code;
  void *address;
  int res = getBase(pi.hProcess, &address, &orig_code);
  if(!res) {
    return res;
  }
  
  WriteProcessMemory(pi.hProcess, address, (char *) &lock_code, 2, 0);
  
  CONTEXT ct;
  ct.ContextFlags = CONTEXT_CONTROL;
  int tries = 0;
  do {
    ResumeThread(pi.hThread);
    Sleep(10);
    SuspendThread(pi.hThread);
    
    if (!GetThreadContext(pi.hThread, &ct)) {
      if (tries++ < 500)
        continue;
      Sleep(100);
      TerminateProcess(pi.hProcess, 1);
      return 8;
    }
  } while (ct.Eip != address);
  
  res = hookDLL(dll_path, &pi);
  if (!res)
    return res;
  
  WriteProcessMemory(pi.hProcess, address, (char *) &orig_code, 2, 0);
  FlushInstructionCache(pi.hProcess, address, 2);
  ResumeThread(pi.hThread);
  
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Syntax: <dll_path> <exe_path> [exe_arg1 [...]]");
    return 1;
  }
  
  return hook(argv[0], argv[1], &argv[2], argc - 2);
}

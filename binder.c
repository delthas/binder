#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

typedef WINSOCK_API_LINKAGE int WINAPI (*__connect)(SOCKET s, const struct sockaddr *name, int namelen);
__connect _connect;

FILE *f;

extern __attribute__ ((unused)) BOOL APIENTRY
DllMain(HMODULE __attribute__((unused)) hMod, DWORD reason, LPVOID __attribute__((unused)) lpReserved) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:;
      f = fopen("file.txt", "w");
      if (f == NULL) {
        printf("Error opening file!\n");
        exit(1);
      }
      fprintf(f, "owo: %s\n", "cc");
      fflush(f);
      HINSTANCE ws2 = LoadLibrary("Ws2_32.dll");
      if (!ws2) {
        fprintf(f, "Cannot load Ws2_32.dll [%d]!\n", (int) GetLastError());
        fflush(f);
      }
      _connect = (__connect) GetProcAddress(ws2, "connect");
      if (!_connect) {
        fprintf(f, "Cannot load connect [%d]!\n", (int) GetLastError());
        fflush(f);
      }
      break;
    case DLL_PROCESS_DETACH:
      fprintf(f, "det: %s\n", "cc");
      fclose(f);
      break;
    case DLL_THREAD_ATTACH:
      fprintf(f, "tat: %s\n", "cc");
      fflush(f);
      break;
    case DLL_THREAD_DETACH:
      fprintf(f, "tdt: %s\n", "cc");
      fflush(f);
    default:
      break;
  }
  
  return TRUE;
}

extern WINSOCK_API_LINKAGE int WINAPI
connect(SOCKET s, const struct sockaddr *name, int namelen) {
  fprintf(f, "cc: %s\n", "cc");
  fflush(f);
  
  struct sockaddr_in service;
  service.sin_family = name->sa_family;
  service.sin_addr.s_addr = inet_addr("127.0.0.1");
  service.sin_port = htons(27015);
  
  int res = bind(s, (SOCKADDR *) &service, sizeof(service));
  fprintf(f, "bind: %d\n", res);
  fflush(f);
  if (res == SOCKET_ERROR) {
    printf("injected bind failed with error %u\n", WSAGetLastError());
    return res;
  }
  res = _connect(s, name, namelen);
  fprintf(f, "connect: %d\n", res);
  fflush(f);
  return res;
}

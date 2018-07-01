#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

typedef DECLSPEC_IMPORT int WINAPI (*__connect)(SOCKET s, const struct sockaddr *name, int namelen);
__connect _connect;

extern BOOL APIENTRY
DllMain(HMODULE __attribute__((unused)) hMod, DWORD reason, LPVOID __attribute__((unused)) lpReserved) __attribute__ ((unused)) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:;
      HINSTANCE ws2 = LoadLibrary("Ws2_32.dll");
      _connect = (__connect) GetProcAddress(ws2, "connect");
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
    default:
      break;
  }
  
  return TRUE;
}

extern DECLSPEC_IMPORT int WINAPI connect(SOCKET s, const struct sockaddr *name, int namelen) __attribute__ ((unused)) {
  struct sockaddr_in service;
  service.sin_family = name->sa_family;
  service.sin_addr.s_addr = inet_addr("127.0.0.1");
  service.sin_port = htons(27015);
  
  int res = bind(s, (SOCKADDR *) &service, sizeof(service));
  if (res == SOCKET_ERROR) {
    printf("injected bind failed with error %u\n", WSAGetLastError());
    return res;
  }
  res = _connect(s, name, namelen);
  return res;
}

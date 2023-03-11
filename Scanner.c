/**********************************************************************************************************************
* Scan for processes on the local machine
* Scan each process for signs of malware
**********************************************************************************************************************/

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>

//LPVOID GetImageBase();
//The image base is going to be the same as the HMODULE address for the first module
HMODULE* GetProcessModules(HANDLE);

int main( int argc, char** args, char** envp ) {
  HANDLE hProcess = GetCurrentProcess();
  LPVOID lpImageBase = NULL;
  SIZE_T bytesRead = NULL;

  IMAGE_DOS_HEADER processDosHeader;
  PIMAGE_DOS_HEADER pProcessDosHeader = &processDosHeader;

  HMODULE* lphModules = GetProcessModules(hProcess);
  HMODULE hModule;
  
  /*
  for (int i = 0; i < sizeof(lphModules); i++) {
    hModule = lphModules[i];
    _tprintf(TEXT("HMODULE: 0x%p\n"), hModule);
    MODULEINFO moduleInfo;
    LPMODULEINFO lpModuleInfo = &moduleInfo;

    if (GetModuleInformation(hProcess, hModule, lpModuleInfo, sizeof(moduleInfo))) {
      TCHAR lpBaseName[MAX_PATH];
      GetModuleFileNameEx(hProcess, hModule, lpBaseName, sizeof(lpBaseName) / sizeof(TCHAR));
      _tprintf(_T("BaseName: %s\n"), lpBaseName);

      printf("\tLoad Address: 0x%p\n\tSizeOfImage: %d BYTES\n\tEntry Point: 0x%p\n\n\n",
        lpModuleInfo->lpBaseOfDll,
        lpModuleInfo->SizeOfImage,
        lpModuleInfo->EntryPoint); //This is the program's entry point for main
    }
    else {
      //6 = ERROR_INVALID_HANDLE
      //127 = ERROR_PROC_NOT_FOUND
      printf("Failed.\n%d\n\n", GetLastError());
    }
  }
  */

  pProcessDosHeader = lphModules[0];
  printf("\tMagic Number: %x\n\te_ip: %x\n\te_lfanew: %x\n",
    pProcessDosHeader->e_magic,
    pProcessDosHeader->e_ip,
    pProcessDosHeader->e_lfanew
    );

  return 0;
}

HMODULE* GetProcessModules(HANDLE hProcess) {
  HMODULE* lphModules[20];
  LPDWORD lpcbNeeded;

  EnumProcessModules(hProcess, lphModules, sizeof(lphModules), &lpcbNeeded);

  return lphModules;
}

LPVOID GetImageBase(HANDLE hProcess) {
  if (hProcess == NULL) {
    //Handle error
  }

  HMODULE hModule = NULL;
  SIZE_T bytesRead;

  GetModuleHandleEx(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    (LPCSTR)&main,
    &hModule );

}
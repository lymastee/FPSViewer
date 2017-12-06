// FPSViewer.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>

typedef HMODULE (WINAPI * PfnLoadLibrary)(const wchar_t* lpName);
typedef DWORD (WINAPI * PfnResumeThread)(HANDLE hThread);
typedef DWORD (WINAPI * PfnGetLastError)();
typedef HANDLE (WINAPI * PfnCreateToolhelp32SnapShot)(DWORD dwFlags, DWORD dwProcessID);
typedef BOOL (WINAPI * PfnCloseHandle)(HANDLE hObject);
typedef BOOL (WINAPI * PfnThread32First)(HANDLE hSnapShot, LPTHREADENTRY32 lpte);
typedef BOOL (WINAPI * PfnThread32Next)(HANDLE hSnapShot, LPTHREADENTRY32 lpte);
typedef BOOL (WINAPI * PfnGetThreadTimes)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
typedef LONG (WINAPI * PfnCompareFileTime)(const FILETIME* lpTime1, const FILETIME* lpTime2);
typedef HANDLE (WINAPI * PfnOpenThread)(DWORD, BOOL, DWORD);

struct RemoteParam
{
    wchar_t             lpszLibraryName[64];
    PfnLoadLibrary      fnLoadLibrary;
    HANDLE              hTargetMainThread;  // invalid handle
    PfnResumeThread     fnResumeThread;
    PfnGetLastError     fnGetLastError;
    DWORD               dwProcessID;
    PfnCreateToolhelp32SnapShot fnCreateToolhelp32SnapShot;
    PfnCloseHandle      fnCloseHandle;
    PfnThread32First    fnThread32First;
    PfnThread32Next     fnThread32Next;
    PfnGetThreadTimes   fnGetThreadTimes;
    PfnCompareFileTime  fnCompareFileTime;
    DWORD               dwThreadID;
    PfnOpenThread       fnOpenThread;
};

DWORD __stdcall ThreadProc(LPVOID lParam)
{
    RemoteParam* pParam = (RemoteParam*)lParam;
    pParam->fnLoadLibrary(pParam->lpszLibraryName);
    HANDLE hThread = pParam->fnOpenThread(THREAD_ALL_ACCESS, FALSE, pParam->dwThreadID);
    if(pParam->fnResumeThread(hThread) != 0)
        return pParam->fnGetLastError();
    pParam->fnCloseHandle(hThread);
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if(argc < 2)
    {
        MessageBox(0, L"Please specify target program(*.exe).", L"Error", MB_OK);
        return 0;
    }

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if(!CreateProcess(argv[1], nullptr,
        nullptr, nullptr, FALSE,
        CREATE_SUSPENDED,
        nullptr, nullptr,
        &si,
        &pi)
        )
    {
        DWORD err = GetLastError();
        MessageBox(0, L"CreateProcess failed.", L"Error", MB_OK);
        return -1;
    }

    const DWORD dwThreadSize = 4096;    // sizeof ThreadProc shellcodes
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    void* pRemoteThread = VirtualAllocEx(hTargetProcess, 0, dwThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!WriteProcessMemory(hTargetProcess, pRemoteThread, &ThreadProc, dwThreadSize, 0))
    {
        DWORD err = GetLastError();
        MessageBox(0, L"WriteProcessMemory failed.", L"Error", MB_OK);
        return -1;
    }

    RemoteParam remoteParam;
    HMODULE hKernel32 = LoadLibrary(L"kernel32.dll");
    remoteParam.fnLoadLibrary = (PfnLoadLibrary)GetProcAddress(hKernel32, "LoadLibraryW");
    remoteParam.fnResumeThread = (PfnResumeThread)GetProcAddress(hKernel32, "ResumeThread");
    remoteParam.hTargetMainThread = pi.hThread;
    remoteParam.fnGetLastError = (PfnGetLastError)GetProcAddress(hKernel32, "GetLastError");
    remoteParam.dwProcessID = pi.dwProcessId;
    remoteParam.fnCreateToolhelp32SnapShot = (PfnCreateToolhelp32SnapShot)GetProcAddress(hKernel32, "CreateToolhelp32SnapShot");
    remoteParam.fnCloseHandle = (PfnCloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    remoteParam.fnThread32First = (PfnThread32First)GetProcAddress(hKernel32, "Thread32First");
    remoteParam.fnThread32Next = (PfnThread32Next)GetProcAddress(hKernel32, "Thread32Next");
    remoteParam.fnGetThreadTimes = (PfnGetThreadTimes)GetProcAddress(hKernel32, "GetThreadTimes");
    remoteParam.fnCompareFileTime = (PfnCompareFileTime)GetProcAddress(hKernel32, "CompareFileTime");
    remoteParam.dwThreadID = pi.dwThreadId;
    remoteParam.fnOpenThread = (PfnOpenThread)GetProcAddress(hKernel32, "OpenThread");
#ifdef _WIN64
    wcscpy_s(remoteParam.lpszLibraryName, _countof(remoteParam.lpszLibraryName), L"d3d11hook64.dll");
#else
    wcscpy_s(remoteParam.lpszLibraryName, _countof(remoteParam.lpszLibraryName), L"d3d11hook.dll");
#endif
    FreeLibrary(hKernel32);
    RemoteParam* pRemoteParam = (RemoteParam*)VirtualAllocEx(hTargetProcess, 0, sizeof(RemoteParam), MEM_COMMIT, PAGE_READWRITE);
    if(!pRemoteParam)
    {
        DWORD err = GetLastError();
        MessageBox(0, L"Alloc RemoteParam failed.", L"Error", MB_OK);
        return -1;
    }

    if(!WriteProcessMemory(hTargetProcess, pRemoteParam, &remoteParam, sizeof(remoteParam), 0))
    {
        DWORD err = GetLastError();
        MessageBox(0, L"WriteProcessMemory failed.", L"Error", MB_OK);
        return -1;
    }

    DWORD dwWriteBytes = 0;
    HANDLE hRemoteThread = CreateRemoteThread(hTargetProcess, nullptr, 0, (DWORD(__stdcall *)(void *))pRemoteThread, pRemoteParam, 0, &dwWriteBytes);
    if(!hRemoteThread)
    {
        DWORD err = GetLastError();
        MessageBox(0, L"CreateRemoteThread failed.", L"Error", MB_OK);
        return -1;
    }

    Sleep(1000);
    DWORD dwExitCode;
    GetExitCodeThread(hRemoteThread, &dwExitCode);
    CloseHandle(hTargetProcess);

    return dwExitCode;
}


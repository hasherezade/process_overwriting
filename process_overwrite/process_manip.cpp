#include "process_manip.h"
#include <peconv.h>
#include <iostream>

#ifndef PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF
#define PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF (0x00000002ui64 << 40) 
#endif

using namespace peconv;

bool create_nocfg_attributes(STARTUPINFOEXA &siex)
{
    memset(&siex, 0, sizeof(STARTUPINFOEXA));
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SIZE_T cbAttributeListSize = 0;
    ULONGLONG MitgFlags = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF;

    // turn off the MITIGATION_POLICY CFG for child process
    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);// cannot be used to check return error -> MSDN (This initial call will return an error by design. This is expected behavior.)
    if (!cbAttributeListSize)
    {
        std::cerr << "[ERROR] InitializeProcThreadAttributeList failed to get the necessary size of the attribute list, Error = 0x" << std::hex << GetLastError() << "\n";
        return false;
    }
    BYTE* attrListBuf = new BYTE[cbAttributeListSize];
    memset(attrListBuf, 0, cbAttributeListSize);

    if (!attrListBuf)
    {
        std::cerr << "[ERROR] Failed to allocate memory for attribute list, Error = 0x" << std::hex << GetLastError() << "\n";
        return false;
    }

    if (!InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)attrListBuf, 1, 0, &cbAttributeListSize))
    {
        std::cerr << "[ERROR] InitializeProcThreadAttributeList failed to initialize the attribute list, Error = 0x" << std::hex << GetLastError() << "\n";
        free(siex.lpAttributeList);
        siex.lpAttributeList = NULL;
        return false;
    }

    if (!UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)attrListBuf, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &MitgFlags, sizeof(MitgFlags), nullptr, 0))
    {
        std::cerr << "[ERROR] UpdateProcThreadAttribute failed, Error = 0x" << std::hex << GetLastError() << "\n";
        return false;
    }
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrListBuf;
    return true;
}

void free_nocfg_attributes(STARTUPINFOEXA& siex)
{
    if (siex.lpAttributeList) {
        DeleteProcThreadAttributeList(siex.lpAttributeList);
        BYTE* attr = (BYTE*)siex.lpAttributeList;
        delete []attr;
        siex.lpAttributeList = NULL;
    }
}


bool create_suspended_process(IN const char* path, IN const char* cmdLine, IN bool disableCfg, OUT PROCESS_INFORMATION &pi)
{
    DWORD process_flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;

    STARTUPINFOEXA siex = { 0 };
    LPSTARTUPINFOA siex_ptr =  NULL;
    if (disableCfg) {
        process_flags |= EXTENDED_STARTUPINFO_PRESENT;
        if (!create_nocfg_attributes(siex)) {
            free_nocfg_attributes(siex);
            return false;
        }
        siex_ptr = (LPSTARTUPINFO) &siex;
    }

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(
            path,
            (LPSTR)cmdLine,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            FALSE, //bInheritHandles
            process_flags, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            siex_ptr, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        std::cerr << "[ERROR] CreateProcess failed, Error = " << std::hex << "0x" << GetLastError() << "\n";
        return false;
    }
    free_nocfg_attributes(siex);
    return true;
}

bool terminate_process(DWORD pid)
{
    bool is_killed = false;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        return false;
    }
    if (TerminateProcess(hProcess, 0)) {
        is_killed = true;
    }
    else {
        std::cerr << "[ERROR] Could not terminate the process. PID = " << std::dec << pid << std::endl;
    }
    CloseHandle(hProcess);
    return is_killed;
}

BOOL update_remote_entry_point(PROCESS_INFORMATION &pi, ULONGLONG entry_point_va, bool is32bit)
{
#ifdef _DEBUG
    std::cout << "Writing new EP: " << std::hex << entry_point_va << std::endl;
#endif
#if defined(_WIN64)
    if (is32bit) {
        // The target is a 32 bit executable while the loader is 64bit,
        // so, in order to access the target we must use Wow64 versions of the functions:

        // 1. Get initial context of the target:
        WOW64_CONTEXT context = { 0 };
        memset(&context, 0, sizeof(WOW64_CONTEXT));
        context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi.hThread, &context)) {
            return FALSE;
        }
        // 2. Set the new Entry Point in the context:
        context.Eax = static_cast<DWORD>(entry_point_va);

        // 3. Set the changed context into the target:
        return Wow64SetThreadContext(pi.hThread, &context);
    }
#endif
    // 1. Get initial context of the target:
    CONTEXT context = { 0 };
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &context)) {
        return FALSE;
    }
    // 2. Set the new Entry Point in the context:
#if defined(_WIN64)
    context.Rcx = entry_point_va;
#else
    context.Eax = static_cast<DWORD>(entry_point_va);
#endif
    // 3. Set the changed context into the target:
    return SetThreadContext(pi.hThread, &context);
}

ULONGLONG get_remote_peb_addr(PROCESS_INFORMATION &pi, bool is32bit)
{
#if defined(_WIN64)
    if (is32bit) {
        //get initial context of the target:
        WOW64_CONTEXT context;
        memset(&context, 0, sizeof(WOW64_CONTEXT));
        context.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi.hThread, &context)) {
            printf("Wow64 cannot get context!\n");
            return 0;
        }
        //get remote PEB from the context
        return static_cast<ULONGLONG>(context.Ebx);
    }
#endif
    ULONGLONG PEB_addr = 0;
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &context)) {
        return 0;
    }
#if defined(_WIN64)
    PEB_addr = context.Rdx;
#else
    PEB_addr = context.Ebx;
#endif
    return PEB_addr;
}

inline ULONGLONG get_img_base_peb_offset(bool is32bit)
{
/*
We calculate this offset in relation to PEB,
that is defined in the following way
(source "ntddk.h"):

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace; // size: 1
    BOOLEAN ReadImageFileExecOptions; // size : 1
    BOOLEAN BeingDebugged; // size : 1
    BOOLEAN SpareBool; // size : 1
                    // on 64bit here there is a padding to the sizeof ULONGLONG (DWORD64)
    HANDLE Mutant; // this field have DWORD size on 32bit, and ULONGLONG (DWORD64) size on 64bit
                   
    PVOID ImageBaseAddress;
    [...]
    */
    ULONGLONG img_base_offset = is32bit ? 
        sizeof(DWORD) * 2
        : sizeof(ULONGLONG) * 2;

    return img_base_offset;
}

ULONGLONG get_remote_img_base(PROCESS_INFORMATION& pi, bool is32bit)
{
    //1. Get access to the remote PEB:
    ULONGLONG remote_peb_addr = get_remote_peb_addr(pi, is32bit);
    if (!remote_peb_addr) {
        std::cerr << "Failed getting remote PEB address!\n";
        return NULL;
    }
    // get the offset to the PEB's field where the ImageBase should be saved (depends on architecture):
    LPVOID remote_img_base = (LPVOID)(remote_peb_addr + get_img_base_peb_offset(is32bit));
    //calculate size of the field (depends on architecture):
    const size_t img_base_size = is32bit ? sizeof(DWORD) : sizeof(ULONGLONG);

    ULONGLONG load_base = 0;
    SIZE_T read = 0;
    //2. Read the ImageBase fron the remote process' PEB:
    if (!ReadProcessMemory(pi.hProcess, remote_img_base,
        &load_base, img_base_size,
        &read))
    {
        std::cerr << "Cannot read ImageBaseAddress!\n";
        return NULL;
    }
    return load_base;
}

bool redirect_to_payload(BYTE* loaded_pe, ULONGLONG load_base, PROCESS_INFORMATION &pi, bool is32bit)
{
    //1. Calculate VA of the payload's EntryPoint
    DWORD ep = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = load_base + ep;

    //2. Write the new Entry Point into context of the remote process:
    if (update_remote_entry_point(pi, ep_va, is32bit) == FALSE) {
        std::cerr << "Cannot update remote EP!\n";
        return false;
    }
    return true;
}


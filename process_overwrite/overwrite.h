#pragma once

#include <windows.h>

bool overwrite_mapping(HANDLE hProcess, HMODULE remoteBase, BYTE* implant_buf, size_t implant_size);

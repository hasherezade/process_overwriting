#pragma once

#include <windows.h>

bool create_suspended_process(IN const char* path, IN const char* cmdLine, OUT PROCESS_INFORMATION& pi);

ULONGLONG get_remote_img_base(PROCESS_INFORMATION& pi, bool is32bit);

bool terminate_process(DWORD pid);

bool redirect_to_payload(BYTE* loaded_pe, ULONGLONG load_base, PROCESS_INFORMATION& pi, bool is32bit);


#include <Windows.h>

#define PECONV_PROJECT_EXPORTS
#include "api.h"

//replace by your own DLL name, update "main.def"
#define LIB_NAME "TemplateDLL"

//replace by your own function, update "api.h" and "main.def"
void __stdcall demo_export(void)
{
	MessageBox(NULL, "PEconv Project", LIB_NAME, MB_ICONINFORMATION);
}

BOOL WINAPI DllMain (HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

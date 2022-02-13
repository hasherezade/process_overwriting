#pragma once

#include <Windows.h>

#ifdef PECONV_PROJECT_EXPORTS
#define PECONV_PROJECT_API __declspec(dllexport)
#else
#define PECONV_PROJECT_API __declspec(dllimport)
#endif

extern "C" {
	//replace by your own function:
	void PECONV_PROJECT_API __stdcall demo_export(void);
};

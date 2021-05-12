#include "../memeye/memeye.h"

#if ME_COMPILER == ME_COMPILER_MSVC
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	printf("[*] Library Loaded\n");
	return TRUE;
}
#else
void __attribute__((constructor)) lib_main()
{
	printf("[*] Library Loaded\n");
}
#endif
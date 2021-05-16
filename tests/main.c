#include "../memeye/memeye.h"

#if ME_CHARSET == ME_CHARSET_UC
#define tprintf wprintf
#else
#define tprintf printf
#endif

#if ME_OS == ME_OS_WIN
#define TARGET_PROCESS "target.exe"
#elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
#define TARGET_PROCESS "target"
#endif

#ifndef LIBTEST_PATH
#define LIBTEST_PATH ""
#endif

int main()
{
	me_pid_t     pid;
	me_pid_t     ppid;
	me_tchar_t   proc_path[ME_PATH_MAX];
	me_tchar_t   proc_name[ME_PATH_MAX];
	me_module_t  mod;
	me_tchar_t   mod_path[ME_PATH_MAX];
	me_tchar_t   mod_name[ME_PATH_MAX];
	me_page_t    page;
	me_address_t alloc;
	me_tstring_t lib_path = LIBTEST_PATH;
	int buf;

	/* Internal */
	tprintf(ME_STR("[*] Internal Test\n"));

	pid = ME_GetProcess();
	ME_OpenProcess(pid);
	tprintf(ME_STR("[*] Process ID: %i\n"), pid);

	ppid = ME_GetProcessParent();
	tprintf(ME_STR("[*] Parent Process ID: %i\n"), ppid);

	memset((void *)proc_path, 0x0, sizeof(proc_path));
	ME_GetProcessPath(proc_path, ME_ARRLEN(proc_path));
	tprintf(ME_STR("[*] Process Path: %s\n"), proc_path);

	memset((void *)proc_name, 0x0, sizeof(proc_name));
	ME_GetProcessName(proc_name, ME_ARRLEN(proc_name));
	tprintf(ME_STR("[*] Process Name: %s\n"), proc_name);

	memset((void *)&mod, 0x0, sizeof(mod));
	ME_GetModule(proc_path, &mod);
	tprintf(ME_STR("[*] Module Base: %p\n"), mod.base);
	tprintf(ME_STR("[*] Module Size: %p\n"), (void *)mod.size);
	tprintf(ME_STR("[*] Module End:  %p\n"), mod.end);

	memset((void *)mod_path, 0x0, sizeof(mod_path));
	ME_GetModulePath(mod, mod_path, ME_ARRLEN(mod_path));
	tprintf(ME_STR("[*] Module Path: %s\n"), mod_path);

	memset((void *)mod_name, 0x0, sizeof(mod_name));
	ME_GetModuleName(mod, mod_name, ME_ARRLEN(mod_name));
	tprintf(ME_STR("[*] Module Name: %s\n"), mod_name);

	alloc = ME_AllocateMemory(sizeof(buf), ME_PROT_XRW);
	tprintf(ME_STR("[*] Allocation Address: %p\n"), alloc);

	memset((void *)&page, 0x0, sizeof(page));
	ME_GetPage(alloc, &page);
	tprintf(ME_STR("[*] Page Base: %p\n"), page.base);
	tprintf(ME_STR("[*] Page Size: %p\n"), (void *)page.size);
	tprintf(ME_STR("[*] Page End:  %p\n"), page.end);
	tprintf(ME_STR("[*] Page Protection: %d\n"), page.prot);
	tprintf(ME_STR("[*] Page Flags: %d\n"), page.flags);

	buf = 1337;
	ME_WriteMemory(alloc, (me_byte_t *)&buf, sizeof(buf));
	tprintf(ME_STR("[*] Written Value: %d\n"), buf);

	buf = 0;
	ME_ReadMemory(alloc, (me_byte_t *)&buf, sizeof(buf));
	tprintf(ME_STR("[*] Read Value: %d\n"), buf);

	ME_FreeMemory(alloc, sizeof(buf));

	memset((void *)&mod, 0x0, sizeof(mod));
	ME_LoadModule(lib_path, &mod);
	tprintf(ME_STR("[*] Library Module Base: %p\n"), mod.base);
	tprintf(ME_STR("[*] Library Module Size: %p\n"), (void *)mod.size);
	tprintf(ME_STR("[*] Library Module End:  %p\n"), mod.end);
	ME_UnloadModule(mod);

	tprintf(ME_STR("[#] ####################\n"));
	ME_CloseProcess(pid);
	/* External */
	tprintf(ME_STR("[*] External Test\n"));

	pid = ME_GetProcessEx(ME_STR(TARGET_PROCESS));
	ME_OpenProcess(pid);
	tprintf(ME_STR("[*] Process ID: %i\n"), pid);

	if (pid == (me_pid_t)ME_BAD)
	{
		tprintf(ME_STR("[!] Target Process Not Running\n"));
		return -1;
	}

	ppid = ME_GetProcessParentEx(pid);
	tprintf(ME_STR("[*] Parent Process ID: %i\n"), ppid);

	memset((void *)proc_path, 0x0, sizeof(proc_path));
	ME_GetProcessPathEx(pid, proc_path, ME_ARRLEN(proc_path));
	tprintf(ME_STR("[*] Process Path: %s\n"), proc_path);

	memset((void *)proc_name, 0x0, sizeof(proc_name));
	ME_GetProcessNameEx(pid, proc_name, ME_ARRLEN(proc_name));
	tprintf(ME_STR("[*] Process Name: %s\n"), proc_name);

	memset((void *)&mod, 0x0, sizeof(mod));
	ME_GetModuleEx(pid, proc_path, &mod);
	tprintf(ME_STR("[*] Module Base: %p\n"), mod.base);
	tprintf(ME_STR("[*] Module Size: %p\n"), (void *)mod.size);
	tprintf(ME_STR("[*] Module End:  %p\n"), mod.end);

	memset((void *)mod_path, 0x0, sizeof(mod_path));
	ME_GetModulePathEx(pid, mod, mod_path, ME_ARRLEN(mod_path));
	tprintf(ME_STR("[*] Module Path: %s\n"), mod_path);

	memset((void *)mod_name, 0x0, sizeof(mod_name));
	ME_GetModuleNameEx(pid, mod, mod_name, ME_ARRLEN(mod_name));
	tprintf(ME_STR("[*] Module Name: %s\n"), mod_name);

	alloc = ME_AllocateMemoryEx(pid, sizeof(buf), ME_PROT_XRW);
	tprintf(ME_STR("[*] Allocation Address: %p\n"), alloc);

	memset((void *)&page, 0x0, sizeof(page));
	ME_GetPageEx(pid, alloc, &page);
	tprintf(ME_STR("[*] Page Base: %p\n"), page.base);
	tprintf(ME_STR("[*] Page Size: %p\n"), (void *)page.size);
	tprintf(ME_STR("[*] Page End:  %p\n"), page.end);
	tprintf(ME_STR("[*] Page Protection: %d\n"), page.prot);
	tprintf(ME_STR("[*] Page Flags: %d\n"), page.flags);

	buf = 1337;
	ME_WriteMemoryEx(pid, alloc, (me_byte_t *)&buf, sizeof(buf));
	tprintf(ME_STR("[*] Written Value: %d\n"), buf);

	buf = 0;
	ME_ReadMemoryEx(pid, alloc, (me_byte_t *)&buf, sizeof(buf));
	tprintf(ME_STR("[*] Read Value: %d\n"), buf);

	ME_FreeMemoryEx(pid, alloc, sizeof(buf));

	memset((void *)&mod, 0x0, sizeof(mod));
	tprintf(ME_STR("[*] Library Path: %s\n"), lib_path);
	ME_LoadModuleEx(pid, lib_path, &mod);
	tprintf(ME_STR("[*] Library Module Base: %p\n"), mod.base);
	tprintf(ME_STR("[*] Library Module Size: %p\n"), (void *)mod.size);
	tprintf(ME_STR("[*] Library Module End:  %p\n"), mod.end);
	ME_UnloadModuleEx(pid, mod);
	ME_CloseProcess(pid);

	tprintf(ME_STR("[#] ####################\n"));
	tprintf(ME_STR("[+] Tests Finished Successfully\n"));

	return 0;
}
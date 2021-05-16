/*
 *                                            
 *  _ __ ___    ___  _ __ ___    ___  _   _   ___ 
 * | '_ ` _ \  / _ \| '_ ` _ \  / _ \| | | | / _ \
 * | | | | | ||  __/| | | | | ||  __/| |_| ||  __/
 * |_| |_| |_| \___||_| |_| |_| \___| \__, | \___|
 *                                     __/ |      
 *                by rdbo             |___/       
 */

#ifndef MEMEYE_H
#define MEMEYE_H

/* Operating System */
#define ME_OS_WIN   0
#define ME_OS_LINUX 1
#define ME_OS_BSD   2

#if (defined(WIN32) || defined(_WIN32) || defined(__WIN32)) && \
    !defined(__CYGWIN__) && !defined(linux)
#define ME_OS ME_OS_WIN
#elif defined(linux) || defined(__linux__)
#define ME_OS ME_OS_LINUX
#elif defined(BSD) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define ME_OS ME_OS_BSD
#endif

/* Architecture */
#define ME_ARCH_UNKNOWN 0
#define ME_ARCH_X86     1

#if defined(_M_X64) || defined(__LP64__) || defined(_LP64) || \
    defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
#define ME_ARCH ME_ARCH_X86
#else
#define ME_ARCH ME_ARCH_UNKNOWN
#endif

#if defined(_M_X64) || defined(__LP64__) || defined(_LP64) || \
    defined(__x86_64__)
#define ME_ARCH_SIZE 64
#else
#define ME_ARCH_SIZE 32
#endif

/* Compiler */
#define ME_COMPILER_MSVC 0
#define ME_COMPILER_CC   1

#ifdef _MSC_VER
#define ME_COMPILER ME_COMPILER_MSVC
#else
#define ME_COMPILER ME_COMPILER_CC
#endif

/* Charset */
#define ME_CHARSET_UC  0
#define ME_CHARSET_MB  1

#if defined(_UNICODE) && ME_OS == ME_OS_WIN
#define ME_CHARSET ME_CHARSET_UC
#else
#define ME_CHARSET ME_CHARSET_MB
#endif

/* Language */
#define ME_LANG_C   0
#define ME_LANG_CPP 1
#if defined(__cplusplus)
#define ME_LANG ME_LANG_CPP
#else
#define ME_LANG ME_LANG_C
#endif

/* Compatibility */
#if defined(ME_OS) && defined(ME_ARCH) && defined(ME_ARCH_SIZE) && \
    defined(ME_COMPILER) && defined(ME_CHARSET) && defined(ME_LANG)
#define ME_COMPATIBLE 1
#endif

/* Helpers */
#if ME_CHARSET == ME_CHARSET_UC
#define ME_STR(wstr) L##str
#define ME_STRCMP    wcscmp
#define ME_STRNCMP   wcsncmp
#define ME_STRLEN    wcslen
#define ME_STRCHR    wcschr
#define ME_STRRCHR   wcsrchr
#define ME_STRSTR    wcsstr
#define ME_STRTOL    wcstol
#if ME_ARCH_SIZE == 64
#define ME_STRTOP    wcstoull
#else
#define ME_STRTOP    wcstoul
#endif
#define ME_ATOI      atoi
#define ME_SNPRINTF  snwprintf
#elif ME_CHARSET == ME_CHARSET_MB
#define ME_STR(str)  str
#define ME_STRCMP    strcmp
#define ME_STRNCMP   strncmp
#define ME_STRLEN    strlen
#define ME_STRCHR    strchr
#define ME_STRRCHR   strrchr
#define ME_STRSTR    strstr
#define ME_STRTOL    strtol
#if ME_ARCH_SIZE == 64
#define ME_STRTOP    strtoull
#else
#define ME_STRTOP    strtoul
#endif
#define ME_ATOI      atoi
#define ME_SNPRINTF  snprintf
#endif
#define ME_MALLOC    malloc
#define ME_CALLOC    calloc
#define ME_FREE      free
#define ME_MEMCPY    memcpy
#define ME_ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

/* Flags */
#if ME_OS == ME_OS_WIN
#define ME_PROT_X   PAGE_EXECUTE
#define ME_PROT_R   PAGE_READONLY
#define ME_PROT_W   PAGE_WRITECOPY
#define ME_PROT_RW  PAGE_READWRITE
#define ME_PROT_XR  PAGE_EXECUTE_READ
#define ME_PROT_XRW PAGE_EXECUTE_READWRITE
#define ME_ALLOC_DEFAULT (MEM_COMMIT | MEM_RESERVE)
#elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
#define ME_PROT_X   PROT_EXEC
#define ME_PROT_R   PROT_READ
#define ME_PROT_W   PROT_WRITE
#define ME_PROT_RW  (PROT_READ | PROT_WRITE)
#define ME_PROT_XR  (PROT_EXEC | PROT_READ)
#define ME_PROT_XRW (PROT_EXEC | PROT_READ | PROT_WRITE)
#define ME_ALLOC_DEFAULT (MAP_PRIVATE | MAP_ANON)
#endif
#define ME_FLAG_AUTO 0

/* Others */
#define ME_NULL  0
#define ME_NULLPTR (me_void_t *)ME_NULL
#define ME_FALSE 0
#define ME_TRUE  (!ME_FALSE)
#define ME_BAD  -1
#define ME_GOOD (!ME_BAD)
#if ME_OS == ME_OS_WIN
#define ME_PATH_MAX MAX_PATH
#elif ME_OS == ME_OS_LINUX
#define ME_PATH_MAX PATH_MAX
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#elif ME_OS == ME_OS_BSD
#define ME_PATH_MAX PATH_MAX
#endif

#if defined(ME_EXPORT)
#if ME_COMPILER == ME_COMPILER_MSVC
#define ME_API __declspec(dllexport)
#elif ME_COMPILER == ME_COMPILER_CC
#define ME_API __attribute__((visibility("default")))
#endif
#elif defined(ME_IMPORT)
#if ME_COMPILER == ME_COMPILER_MSVC
#define ME_API __declspec(dllimport)
#elif ME_COMPILER == ME_COMPILER_CC
#define ME_API extern
#endif
#else
#define ME_API
#endif

#if ME_COMPATIBLE

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <memory.h>
#include <malloc.h>
#if ME_OS == ME_OS_WIN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#elif ME_OS == ME_OS_LINUX
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/io.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#elif ME_OS == ME_OS_BSD
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <machine/reg.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#include <libprocstat.h>
#include <paths.h>
#endif

/* Enums */
enum
{
#   if ME_ARCH == ME_ARCH_X86
    ME_DETOUR_JMP32,
    /*
     * JMP *<REL_ADDR>
     */
    ME_DETOUR_JMP64,
    /*
     * JMP *[RIP]
     * <ABS_ADDR>
     */
    ME_DETOUR_CALL32,
    /*
     * CALL *<REL_ADDR>
     *
     */
    ME_DETOUR_CALL64,
    /*
     * CALL *[RIP]
     * <ABS_ADDR>
     */
#   endif
    ME_DETOUR_INVAL
};

enum
{
#   if ME_ARCH == ME_ARCH_X86
#   if ME_ARCH_SIZE == 64
    ME_REGID_RAX,
    ME_REGID_RBX,
    ME_REGID_RCX,
    ME_REGID_RDX,
    ME_REGID_RSI,
    ME_REGID_RDI,
    ME_REGID_RBP,
    ME_REGID_RSP,
    ME_REGID_RIP,
    ME_REGID_R8,
    ME_REGID_R9,
    ME_REGID_R10,
    ME_REGID_R11,
    ME_REGID_R12,
    ME_REGID_R13,
    ME_REGID_R14,
    ME_REGID_R15,
#   else
    ME_REGID_EAX,
    ME_REGID_EBX,
    ME_REGID_ECX,
    ME_REGID_EDX,
    ME_REGID_ESI,
    ME_REGID_EDI,
    ME_REGID_EBP,
    ME_REGID_ESP,
    ME_REGID_EIP,
#   endif
#   endif
    ME_REGID_INVAL
};

/* Types */
typedef void             me_void_t;
typedef int              me_int_t;
typedef unsigned int     me_uint_t;
typedef me_int_t         me_bool_t;

typedef signed char      me_int8_t;
typedef signed short     me_int16_t;
typedef signed int       me_int32_t;
typedef signed long      me_int64_t;

typedef unsigned char    me_uint8_t;
typedef unsigned short   me_uint16_t;
typedef unsigned int     me_uint32_t;
typedef unsigned long    me_uint64_t;

typedef me_uint8_t       me_byte_t;
typedef me_uint16_t      me_word_t;
typedef me_uint32_t      me_dword_t;
typedef me_uint64_t      me_qword_t;

typedef long             me_intptr_t;
typedef unsigned long    me_uintptr_t;
typedef me_void_t       *me_voidptr_t;

typedef size_t           me_size_t;
typedef me_voidptr_t     me_address_t;

typedef char             me_char_t;
typedef wchar_t          me_wchar_t;
#if ME_CHARSET == ME_CHARSET_UC
typedef me_wchar_t       me_tchar_t;
#else
typedef me_char_t        me_tchar_t;
#endif

typedef me_char_t       *me_cstring_t;
typedef me_wchar_t      *me_wstring_t;
typedef me_tchar_t      *me_tstring_t;
#if ME_LANG == ME_LANG_C
typedef me_tstring_t     me_string_t;
#endif

#if ME_OS == ME_OS_WIN
typedef DWORD            me_pid_t;
typedef DWORD            me_prot_t;
typedef DWORD            me_flags_t;
typedef CONTEXT          me_regs_t;
#elif ME_OS == ME_OS_LINUX
typedef pid_t            me_pid_t;
typedef me_int_t         me_prot_t;
typedef me_int_t         me_flags_t;
typedef struct user_regs_struct
                         me_regs_t;
#elif ME_OS == ME_OS_BSD
typedef pid_t            me_pid_t;
typedef me_int_t         me_prot_t;
typedef me_int_t         me_flags_t;
typedef struct reg       me_regs_t;
#endif
typedef me_int_t         me_arch_t;
typedef me_int_t         me_detour_t;
typedef me_int_t         me_regid_t;

typedef struct me_module_t
{
	me_address_t base;
	me_size_t    size;
	me_address_t end;
} me_module_t;

typedef struct me_page_t
{
	me_address_t base;
	me_size_t    size;
	me_address_t end;
	me_prot_t    prot;
    me_flags_t   flags;
} me_page_t;

/* MemEye */
ME_API void *
ME_malloc(size_t size);

ME_API void *
ME_calloc(size_t nmemb,
          size_t size);

ME_API void
ME_free(void *ptr);

/****************************************/

ME_API me_bool_t
ME_EnumProcesses(me_bool_t(*callback)(me_pid_t   pid,
                                      me_void_t *arg),
                 me_void_t *arg);

ME_API me_bool_t
ME_OpenProcess(me_pid_t pid);

ME_API me_bool_t
ME_CloseProcess(me_pid_t pid);

ME_API me_pid_t
ME_GetProcessEx(me_tstring_t proc_ref);

ME_API me_pid_t
ME_GetProcess(me_void_t);

ME_API me_size_t
ME_GetProcessPathEx(me_pid_t    pid,
                    me_tchar_t *proc_path,
                    me_size_t   max_len);

ME_API me_size_t
ME_GetProcessPath(me_tchar_t *proc_path,
                  me_size_t   max_len);

ME_API me_size_t
ME_GetProcessNameEx(me_pid_t    pid,
                    me_tchar_t *proc_name,
                    me_size_t   max_len);

ME_API me_size_t
ME_GetProcessName(me_tchar_t *proc_name,
                  me_size_t   max_len);

ME_API me_pid_t
ME_GetProcessParentEx(me_pid_t pid);

ME_API me_pid_t
ME_GetProcessParent(me_void_t);

/****************************************/

ME_API me_bool_t
ME_EnumModulesEx(me_pid_t   pid,
                 me_bool_t(*callback)(me_pid_t    pid,
                                      me_module_t mod,
                                      me_void_t  *arg),
                 me_void_t *arg);

ME_API me_bool_t
ME_EnumModules(me_bool_t(*callback)(me_pid_t    pid,
                                    me_module_t mod,
                                    me_void_t  *arg),
               me_void_t *arg);

ME_API me_bool_t
ME_GetModuleEx(me_pid_t     pid,
               me_tstring_t mod_ref,
               me_module_t *pmod);

ME_API me_bool_t
ME_GetModule(me_tstring_t mod_ref,
             me_module_t *pmod);

ME_API me_bool_t
ME_FindModuleEx(me_pid_t     pid,
                me_tstring_t mod_ref,
                me_module_t *pmod);

ME_API me_bool_t
ME_FindModule(me_tstring_t mod_ref,
              me_module_t *pmod);

ME_API me_size_t
ME_GetModulePathEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_path,
                   me_size_t   max_len);

ME_API me_size_t
ME_GetModulePath(me_module_t mod,
                 me_tchar_t *mod_path,
                 me_size_t   max_len);

ME_API me_size_t
ME_GetModuleNameEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_name,
                   me_size_t   max_len);

ME_API me_size_t
ME_GetModuleName(me_module_t mod,
                 me_tchar_t *mod_name,
                 me_size_t   max_len);

ME_API me_bool_t
ME_LoadModuleEx(me_pid_t     pid,
                me_tstring_t path,
                me_module_t *pmod);

ME_API me_bool_t
ME_LoadModule(me_tstring_t path,
              me_module_t *pmod);

ME_API me_bool_t
ME_UnloadModuleEx(me_pid_t    pid,
                  me_module_t mod);

ME_API me_bool_t
ME_UnloadModule(me_module_t mod);

/****************************************/

ME_API me_bool_t
ME_EnumPagesEx(me_pid_t   pid,
               me_bool_t(*callback)(me_page_t  page,
                                    me_void_t *arg),
               me_void_t *arg);

ME_API me_bool_t
ME_EnumPages(me_bool_t(*callback)(me_page_t  page,
                                  me_void_t *arg),
             me_void_t *arg);

ME_API me_bool_t
ME_GetPageEx(me_pid_t     pid,
             me_address_t addr,
             me_page_t   *ppage);

ME_API me_bool_t
ME_GetPage(me_address_t addr,
           me_page_t   *ppage);

/****************************************/

ME_API me_size_t
ME_ReadMemoryEx(me_pid_t     pid,
                me_address_t src,
                me_byte_t   *dst,
                me_size_t    size);

ME_API me_size_t
ME_ReadMemory(me_address_t src,
              me_byte_t   *dst,
              me_size_t    size);

ME_API me_size_t
ME_WriteMemoryEx(me_pid_t     pid,
                 me_address_t dst,
                 me_byte_t   *src,
                 me_size_t    size);

ME_API me_size_t
ME_WriteMemory(me_address_t dst,
               me_byte_t   *src,
               me_size_t    size);

ME_API me_bool_t
ME_ProtectMemoryEx(me_pid_t     pid,
                   me_address_t addr,
                   me_size_t    size,
                   me_prot_t    prot,
                   me_prot_t   *old_prot);

ME_API me_bool_t
ME_ProtectMemory(me_address_t addr,
                 me_size_t    size,
                 me_prot_t    prot,
                 me_prot_t   *old_prot);

ME_API me_address_t
ME_AllocateMemoryEx(me_pid_t   pid,
                    me_size_t  size,
                    me_prot_t  prot);

ME_API me_address_t
ME_AllocateMemory(me_size_t  size,
                  me_prot_t  prot);

ME_API me_bool_t
ME_FreeMemoryEx(me_pid_t     pid,
                me_address_t addr,
                me_size_t    size);

ME_API me_bool_t
ME_FreeMemory(me_address_t addr,
              me_size_t    size);

ME_API me_size_t
ME_DetourCodeEx(me_pid_t       pid,
                me_address_t   src,
                me_address_t   dst,
                me_detour_t    detour);

ME_API me_size_t
ME_DetourCode(me_address_t   src,
              me_address_t   dst,
              me_detour_t    detour);

ME_API me_size_t
ME_TrampolineCodeEx(me_pid_t     pid,
                    me_address_t src,
                    me_size_t    size,
                    me_address_t tramp,
                    me_size_t    max_size);

ME_API me_size_t
ME_TrampolineCode(me_address_t src,
                  me_size_t    size,
                  me_byte_t   *tramp,
                  me_size_t    max_size);

ME_API me_void_t *
ME_SyscallEx(me_pid_t   pid,
             me_int_t   nsyscall,
             me_void_t *arg0,
             me_void_t *arg1,
             me_void_t *arg2,
             me_void_t *arg3,
             me_void_t *arg4,
             me_void_t *arg5);

ME_API me_void_t *
ME_Syscall(me_int_t   nsyscall,
           me_void_t *arg0,
           me_void_t *arg1,
           me_void_t *arg2,
           me_void_t *arg3,
           me_void_t *arg4,
           me_void_t *arg5);

ME_API me_address_t
ME_GetSymbolEx(me_pid_t     pid,
               me_module_t  mod,
               me_cstring_t symbol);

ME_API me_address_t
ME_GetSymbol(me_module_t  mod,
             me_cstring_t symbol);

/****************************************/

ME_API me_bool_t
ME_AttachDbg(me_pid_t pid);

ME_API me_bool_t
ME_DetachDbg(me_pid_t pid);

ME_API me_int_t
ME_GetStateDbg(me_pid_t pid);

ME_API me_size_t
ME_ReadMemoryDbg(me_pid_t     pid,
                 me_address_t src,
                 me_byte_t   *dst,
                 me_size_t    size);

ME_API me_size_t
ME_WriteMemoryDbg(me_pid_t     pid,
                  me_address_t dst,
                  me_byte_t   *src,
                  me_size_t    size);

ME_API me_bool_t
ME_GetRegsDbg(me_pid_t   pid,
              me_regs_t *pregs);

ME_API me_bool_t
ME_SetRegsDbg(me_pid_t  pid,
              me_regs_t regs);

ME_API me_uintptr_t
ME_ReadRegDbg(me_regid_t   reg,
              me_regs_t    regs);

ME_API me_bool_t
ME_WriteRegDbg(me_uintptr_t val,
               me_regid_t   reg,
               me_regs_t   *pregs);

ME_API me_bool_t
ME_WaitDbg(me_void_t);

ME_API me_bool_t
ME_WaitProcessDbg(me_pid_t pid);

ME_API me_bool_t
ME_ContinueDbg(me_pid_t pid);

ME_API me_bool_t
ME_StepDbg(me_pid_t pid);

ME_API me_bool_t
ME_BreakDbg(me_pid_t pid);

ME_API me_bool_t
ME_KillDbg(me_pid_t pid);

#endif
#endif

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

/* Others */
#define ME_NULL  0
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
#include <stdint.h>
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
    ME_SHELLCODE_JMP32 = 0,
    /*
     * JMP *<REL_ADDR>
     */
    ME_SHELLCODE_JMP64,
    /*
     * JMP *[EIP]
     * <ABS_ADDR>
     */
    ME_SHELLCODE_CALL32,
    /*
     * CALL *<REL_ADDR>
     *
     */
    ME_SHELLCODE_CALL64,
    /*
     * CALL *[RIP]
     * <ABS_ADDR>
     */
#   endif
    ME_SHELLCODE_INVAL
};

enum
{
    ME_DEBUG_FAILED = 0,
    ME_DEBUG_SUCCESS,
    ME_DEBUG_ATTACHED,
    ME_DEBUG_NOT_ATTACHED
};

/* Types */
typedef void         me_void_t;
typedef int          me_int_t;
typedef unsigned int me_uint_t;
typedef me_int_t     me_bool_t;

typedef int8_t       me_int8_t;
typedef int16_t      me_int16_t;
typedef int32_t      me_int32_t;
typedef int64_t      me_int64_t;

typedef uint8_t      me_uint8_t;
typedef uint16_t     me_uint16_t;
typedef uint32_t     me_uint32_t;
typedef uint64_t     me_uint64_t;

typedef me_uint8_t   me_byte_t;
typedef me_uint16_t  me_word_t;
typedef me_uint32_t  me_dword_t;
typedef me_uint64_t  me_qword_t;

typedef intptr_t     me_intptr_t;
typedef uintptr_t    me_uintptr_t;
typedef me_void_t   *me_voidptr_t;

typedef size_t       me_size_t;
typedef me_voidptr_t me_address_t;

typedef char         me_char_t;
typedef wchar_t      me_wchar_t;
#if ME_CHARSET == ME_CHARSET_UC
typedef me_wchar_t   me_tchar_t;
#else
typedef me_char_t    me_tchar_t;
#endif

typedef me_char_t   *me_cstring_t;
typedef me_wchar_t  *me_wstring_t;
typedef me_tchar_t  *me_tstring_t;
#if ME_LANG == ME_LANG_C
typedef me_tstring_t me_string_t;
#endif

#if ME_OS == ME_OS_WIN
typedef DWORD        me_pid_t;
typedef DWORD        me_prot_t;
typedef DWORD        me_flags_t;
#elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
typedef pid_t        me_pid_t;
typedef me_int_t     me_prot_t;
typedef me_int_t     me_flags_t;
#endif
typedef me_int_t     me_arch_t;
typedef me_int_t     me_shellcode_t;
typedef me_int_t     me_debug_t;

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

typedef struct me_regs_t
{
#   if ME_ARCH == ME_ARCH_X86
#   if ME_ARCH_SIZE == 32
    me_uint32_t eax;
    me_uint32_t ebx;
    me_uint32_t ecx;
    me_uint32_t edx;
    me_uint32_t edi;
    me_uint32_t esi;
    me_uint32_t ebp;
    me_uint32_t esp;
    me_uint32_t eip;
    me_uint32_t cs;
    me_uint32_t ds;
    me_uint32_t es;
    me_uint32_t fs;
    me_uint32_t gs;
    me_uint32_t ss;
#   elif ME_ARCH_SIZE == 64
    me_uint64_t rax;
    me_uint64_t rbx;
    me_uint64_t rcx;
    me_uint64_t rdx;
    me_uint64_t rdi;
    me_uint64_t rsi;
    me_uint64_t rbp;
    me_uint64_t rsp;
    me_uint64_t rip;
    me_uint64_t r8;
    me_uint64_t r9;
    me_uint64_t r10;
    me_uint64_t r11;
    me_uint64_t r12;
    me_uint64_t r13;
    me_uint64_t r14;
    me_uint64_t r15;
    me_uint64_t cs;
    me_uint64_t ds;
    me_uint64_t es;
    me_uint64_t fs;
    me_uint64_t gs;
    me_uint64_t ss;
#   endif
#   else
    me_byte_t inval;
#   endif
} me_regs_t;

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
                                      me_void_t  *arg,
                                      me_void_t  *reserved),
                 me_void_t *arg);

ME_API me_bool_t
ME_EnumModules2Ex(me_pid_t   pid,
                  me_bool_t(*callback)(me_pid_t    pid,
                                       me_module_t mod,
                                       me_void_t  *arg,
                                       me_void_t  *reserved),
                  me_void_t *arg,
                  me_void_t *reserved);

ME_API me_bool_t
ME_EnumModules(me_bool_t(*callback)(me_pid_t    pid,
                                    me_module_t mod,
                                    me_void_t  *arg,
                                    me_void_t  *reserved),
               me_void_t *arg);

ME_API me_bool_t
ME_EnumModules2(me_bool_t(*callback)(me_pid_t    pid,
                                     me_module_t mod,
                                     me_void_t  *arg,
                                     me_void_t  *reserved),
                me_void_t *arg,
                me_void_t *reserved);

ME_API me_bool_t
ME_GetModuleEx(me_pid_t     pid,
               me_tstring_t mod_ref,
               me_module_t *pmod);

ME_API me_bool_t
ME_GetModule2Ex(me_pid_t     pid,
                me_tstring_t mod_ref,
                me_module_t *pmod,
                me_void_t   *reserved);

ME_API me_bool_t
ME_GetModule(me_tstring_t mod_ref,
             me_module_t *pmod);

ME_API me_bool_t
ME_GetModule2(me_tstring_t mod_ref,
              me_module_t *pmod,
              me_void_t   *reserved);

ME_API me_size_t
ME_GetModulePathEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_path,
                   me_size_t   max_len);

ME_API me_size_t
ME_GetModulePath2Ex(me_pid_t    pid,
                    me_module_t mod,
                    me_tchar_t *mod_path,
                    me_size_t   max_len,
                    me_void_t  *reserved);

ME_API me_size_t
ME_GetModulePath(me_module_t mod,
                 me_tchar_t *mod_path,
                 me_size_t   max_len);

ME_API me_size_t
ME_GetModulePath2(me_module_t mod,
                  me_tchar_t *mod_path,
                  me_size_t   max_len,
                  me_void_t  *reserved);

ME_API me_size_t
ME_GetModuleNameEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_name,
                   me_size_t   max_len);

ME_API me_size_t
ME_GetModuleName2Ex(me_pid_t    pid,
                    me_module_t mod,
                    me_tchar_t *mod_name,
                    me_size_t   max_len,
                    me_void_t  *reserved);

ME_API me_size_t
ME_GetModuleName(me_module_t mod,
                 me_tchar_t *mod_name,
                 me_size_t   max_len);

ME_API me_size_t
ME_GetModuleName2(me_module_t mod,
                  me_tchar_t *mod_name,
                  me_size_t   max_len,
                  me_void_t  *reserved);

ME_API me_bool_t
ME_LoadModuleEx(me_pid_t     pid,
                me_tstring_t path);

ME_API me_bool_t
ME_LoadModule2Ex(me_pid_t     pid,
                 me_tstring_t path,
                 me_void_t   *reserved);

ME_API me_bool_t
ME_LoadModule(me_tstring_t path);

ME_API me_bool_t
ME_LoadModule2(me_tstring_t path,
               me_void_t   *reserved);

ME_API me_bool_t
ME_UnloadModuleEx(me_pid_t    pid,
                  me_module_t mod);

ME_API me_bool_t
ME_UnloadModule(me_module_t mod);

/****************************************/

ME_API me_bool_t
ME_EnumPagesEx(me_pid_t   pid,
               me_bool_t(*callback)(me_pid_t   pid,
                                    me_page_t  page,
                                    me_void_t *arg),
               me_void_t *arg);

ME_API me_bool_t
ME_EnumPages2Ex(me_pid_t   pid,
                me_bool_t(*callback)(me_pid_t   pid,
                                     me_page_t  page,
                                     me_void_t *arg),
                me_void_t *arg,
                me_void_t *reserved);

ME_API me_bool_t
ME_EnumPages(me_bool_t(*callback)(me_pid_t   pid,
                                  me_page_t  page,
                                  me_void_t *arg),
             me_void_t *arg);

ME_API me_bool_t
ME_EnumPages2(me_bool_t(*callback)(me_pid_t   pid,
                                   me_page_t  page,
                                   me_void_t *arg),
              me_void_t *arg,
              me_void_t *reserved);

ME_API me_bool_t
ME_GetPageEx(me_pid_t     pid,
             me_address_t addr,
             me_page_t   *ppage);

ME_API me_bool_t
ME_GetPage2Ex(me_pid_t     pid,
              me_address_t addr,
              me_page_t   *ppage,
              me_void_t   *reserved);

ME_API me_bool_t
ME_GetPage(me_address_t addr,
           me_page_t   *ppage);

ME_API me_bool_t
ME_GetPage2(me_address_t addr,
            me_page_t   *ppage,
            me_void_t   *reserved);

/****************************************/

ME_API me_size_t
ME_ReadMemoryEx(me_pid_t     pid,
                me_address_t src,
                me_byte_t   *dst,
                me_size_t    size);

ME_API me_bool_t
ME_ReadMemory(me_address_t src,
              me_byte_t   *dst,
              me_size_t    size);

ME_API me_bool_t
ME_WriteMemoryEx(me_pid_t     pid,
                 me_byte_t   *dst,
                 me_address_t src,
                 me_size_t    size);

ME_API me_bool_t
ME_WriteMemory(me_byte_t   *dst,
               me_address_t src,
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
                    me_prot_t  prot,
                    me_flags_t flags);

ME_API me_address_t
ME_AllocateMemory(me_size_t  size,
                  me_prot_t  prot,
                  me_flags_t flags);

ME_API me_bool_t
ME_FreeMemoryEx(me_pid_t     pid,
                me_address_t addr,
                me_size_t    size);

ME_API me_bool_t
ME_FreeMemory(me_address_t addr,
              me_size_t    size);

ME_API me_bool_t
ME_DetourCodeEx(me_pid_t       pid,
                me_address_t   src,
                me_address_t   dst,
                me_shellcode_t shellcode);

ME_API me_bool_t
ME_DetourCode(me_address_t   src,
              me_address_t   dst,
              me_shellcode_t shellcode);

ME_API me_bool_t
ME_TrampolineCodeEx(me_pid_t     pid,
                    me_address_t src,
                    me_byte_t   *dst,
                    me_size_t    size);

ME_API me_bool_t
ME_TrampolineCode(me_address_t src,
                  me_byte_t   *dst,
                  me_size_t    size);

/****************************************/

ME_API me_debug_t
ME_AttachDbg(me_pid_t pid);

ME_API me_debug_t
ME_DetachDbg(me_pid_t pid);

ME_API me_debug_t
ME_GetStateDbg(me_pid_t pid);

ME_API me_debug_t
ME_ReadMemoryDbg(me_pid_t     pid,
                 me_address_t src,
                 me_byte_t   *dst,
                 me_size_t    size);

ME_API me_debug_t
ME_WriteMemoryDbg(me_pid_t     pid,
                  me_address_t dst,
                  me_byte_t   *src,
                  me_size_t    size);

ME_API me_debug_t
ME_GetRegsDbg(me_pid_t   pid,
              me_regs_t *pregs);

ME_API me_debug_t
ME_SetRegsDbg(me_pid_t  pid,
              me_regs_t regs);

#endif
#endif
/*
 *                                            
 *  _ __ ___    ___  _ __ ___    ___  _   _   ___ 
 * | '_ ` _ \  / _ \| '_ ` _ \  / _ \| | | | / _ \
 * | | | | | ||  __/| | | | | ||  __/| |_| ||  __/
 * |_| |_| |_| \___||_| |_| |_| \___| \__, | \___|
 *                                     __/ |      
 *                by rdbo             |___/       
 */

#include "memeye.h"

#if ME_COMPATIBLE

typedef struct _ME_GetProcessExArgs_t
{
    me_pid_t pid;
    me_tstring_t proc_ref;
} _ME_GetProcessExArgs_t;

typedef struct _ME_GetModuleExArgs_t
{
    me_module_t *pmod;
    me_tstring_t mod_ref;
} _ME_GetModuleExArgs_t;

typedef struct _ME_FindModuleExArgs_t
{
    me_module_t *pmod;
    me_tstring_t mod_ref;
} _ME_FindModuleExArgs_t;

typedef struct _ME_GetPageExArgs_t
{
    me_page_t *ppage;
    me_address_t addr;
} _ME_GetPageExArgs_t;

/****************************************/

ME_API void *
ME_malloc(size_t size)
{
    return ME_MALLOC(size);
}

ME_API void *
ME_calloc(size_t nmemb,
          size_t size)
{
    return ME_CALLOC(nmemb, size);
}

ME_API void
ME_free(void *ptr)
{
    ME_FREE(ptr);
}

/****************************************/

ME_API me_bool_t
ME_EnumProcesses(me_bool_t(*callback)(me_pid_t   pid,
                                      me_void_t *arg),
                 me_void_t *arg)
{
    me_bool_t ret = ME_FALSE;

    if (!callback)
        return ret;

#   if   ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &entry))
            {
                do
                {
                    me_pid_t pid = (me_pid_t)entry.th32ProcessID;
                    if (callback(pid, arg) == ME_FALSE)
                        break;
                } while(Process32Next(hSnap, &entry));

                ret = ME_TRUE;
            }

            CloseHandle(hSnap);
        }
    }
#   elif ME_OS == ME_OS_LINUX
    {
        struct dirent *pdirent;
        DIR *dir = opendir(ME_STR("/proc"));
        while ((pdirent = readdir(dir)))
        {
            me_pid_t pid = ME_ATOI(pdirent->d_name);
            if (pid || (!pid && !ME_STRCMP(pdirent->d_name, ME_STR("0"))))
            {
                if (callback(pid, arg) == ME_FALSE)
                    break;
            }
        }
    }
#   elif ME_OS == ME_OS_BSD
    {
        struct procstat *ps = procstat_open_sysctl();
        if (ps)
        {
            unsigned int proc_count = 0;
            struct kinfo_proc *procs = procstat_getprocs(ps, KERN_PROC_PROC, pid, &proc_count);
            if (procs)
            {
                {
                    unsigned int i;
                    for (i = 0; i < proc_count; ++i)
                    {
                        me_pid_t pid = (me_pid_t)procs[i].ki_pid;
                        if (callback(pid, arg) == ME_FALSE)
                            break;
                    }
                }

                ret = ME_TRUE;
                procstat_freeprocs(ps, procs);
            }

            procstat_close(ps);
        }
    }
#   endif

    return ret;
}

static me_bool_t _ME_GetProcessExCallback(me_pid_t   pid,
                                          me_void_t *arg)
{
    _ME_GetProcessExArgs_t *parg = (_ME_GetProcessExArgs_t *)arg;
    me_tchar_t proc_path[ME_PATH_MAX] = { 0 };
    me_size_t proc_path_len;
    if ((proc_path_len = ME_GetProcessPathEx(pid,
                                             proc_path,
                                             ME_ARRLEN(proc_path))))
    {
        me_size_t proc_ref_len = ME_STRLEN(parg->proc_ref);
        if (proc_ref_len <= proc_path_len)
        {
            if (!ME_STRCMP(&proc_path[proc_path_len - proc_ref_len], 
                            parg->proc_ref))
            {
                parg->pid = pid;
                return ME_FALSE;
            }
        }
    }

    return ME_TRUE;
}

ME_API me_pid_t
ME_GetProcessEx(me_tstring_t proc_ref)
{
    _ME_GetProcessExArgs_t arg;
    arg.pid = ME_BAD;
    arg.proc_ref = proc_ref;

    if (arg.proc_ref)
        ME_EnumProcesses(_ME_GetProcessExCallback, (me_void_t *)&arg);
    
    return arg.pid;
}

ME_API me_pid_t
ME_GetProcess(me_void_t)
{
    me_pid_t pid = (me_pid_t)ME_BAD;
#   if ME_OS == ME_OS_WIN
    {
        pid = (me_pid_t)GetCurrentProcessID();
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        pid = (me_pid_t)getpid();
    }
#   endif

    return pid;
}

ME_API me_size_t
ME_GetProcessPathEx(me_pid_t    pid,
                    me_tchar_t *proc_path,
                    me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (pid == (me_pid_t)ME_BAD || !proc_path || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
            return pid;

        chr_count = (me_size_t)GetModuleFileNameEx(hProcess, NULL,
                                                   proc_path, max_len);
        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t exe_path[64] = { 0 };
        ME_SNPRINTF(exe_path, ME_ARRLEN(exe_path) - 1,
                    ME_STR("/proc/%d/exe"), pid);
        chr_count = (me_size_t)readlink(exe_path, proc_path, max_len - 1);
        proc_path[max_len - 1] = ME_STR('\00');
        if (chr_count > 0 && chr_count < max_len)
            proc_path[chr_count] = ME_STR('\00');
    }
#   elif ME_OS == ME_OS_BSD
    {
        struct procstat *ps = procstat_open_sysctl();
        if (ps)
        {
            unsigned int proc_count = 0;
            struct kinfo_proc *pproc = procstat_getprocs(ps, KERN_PROC_PID,
                                                         pid, &proc_count);
            if (pproc && proc_count > 0)
            {
                if (procstat_getpathname(ps, pproc, proc_path, max_len))
                    chr_count = ME_STRLEN(proc_path);

                procstat_freeprocs(ps, procs);
            }
            procstat_close(ps);
        }
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetProcessPath(me_tchar_t *proc_path,
                  me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (!proc_path || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule)
            return chr_count;

        chr_count = (me_size_t)GetModuleFileName(hModule, proc_path, max_len);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        chr_count = ME_GetProcessPathEx(ME_GetProcess(), proc_path, max_len);
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetProcessNameEx(me_pid_t    pid,
                    me_tchar_t *proc_name,
                    me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (pid == (me_pid_t)ME_BAD || !proc_name || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN /* || ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD */
    {
        me_tchar_t proc_path[ME_PATH_MAX] = { 0 };
        if (ME_GetProcessPathEx(pid, proc_path, ME_ARRLEN(proc_path)))
        {
            me_tchar_t path_chr;
            me_tchar_t *tmp;
            me_tchar_t *file_str;

#           if ME_OS == ME_OS_WIN
            path_chr = ME_STR('\\');
#           elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
            path_chr = ME_STR('/');
#           endif

            for (tmp = proc_path;
                 (tmp = ME_STRCHR(tmp, path_chr));
                 tmp = &tmp[1], file_str = tmp);

            chr_count = ME_STRLEN(file_str);
            if (chr_count > max_len)
                chr_count = max_len;

            ME_MEMCPY((void *)proc_name, (void *)file_str,
                      chr_count * sizeof(proc_name[0]));
        }
    }
#   elif ME_OS == ME_OS_LINUX
    {
        int fd;
        me_tchar_t comm_path[64] = { 0 };
        ME_SNPRINTF(comm_path, ME_ARRLEN(comm_path) - 1, 
                    ME_STR("/proc/%d/comm"), pid);

        fd = open(comm_path, O_RDONLY);

        if (fd == -1)
            return chr_count;

        chr_count = read(fd, proc_name, max_len * sizeof(proc_name[0]));

        {
            me_tchar_t *pchr;
            for (pchr = proc_name;
                 pchr != &proc_name[max_len - 1];
                 pchr = &pchr[1])
            {
                if (*pchr == ME_STR('\n'))
                {
                    *pchr = ME_STR('\00');
                    break;
                }
            }

            proc_name[max_len - 1] = ME_STR('\00');
        }
    }
#   elif ME_OS == ME_OS_BSD
    {
        struct procstat *ps = procstat_open_sysctl();
        if (ps)
        {
            unsigned int proc_count = 0;
            struct kinfo_proc *pproc = procstat_getprocs(ps, KERN_PROC_PID, pid, &proc_count);

            if (pproc)
            {
                if (proc_count > 0)
                {
                    chr_count = ME_STRLEN(pproc->ki_comm);
                    if (chr_count > max_len)
                        chr_count = max_len;
                    ME_MEMCPY((void *)proc_name, (void *)pproc->ki_comm, 
                              chr_count * sizeof(proc_name[0]));
                }

                procstat_freeprocs(pproc);
            }

            procstat_close(ps);
        }
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetProcessName(me_tchar_t *proc_name,
                  me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (!proc_name || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        me_tchar_t proc_path[ME_PATH_MAX];
        if (ME_GetProcessPath(proc_path, ME_ARRLEN(proc_path)))
        {
            me_tchar_t path_chr = ME_STR('\\');
            me_tchar_t *tmp;

            for (tmp = proc_path; (tmp = ME_STRCHR(proc_path, path_chr)); tmp = &tmp[1]);

            chr_count = ME_STRLEN(tmp);
            if (chr_count > max_len)
                chr_count = max_len;

            ME_MEMCPY((void *)proc_name, (void *)tmp, 
                      chr_count * sizeof(proc_name[0]));
        }
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        chr_count = ME_GetProcessNameEx(ME_GetProcess(), proc_name, max_len);
    }
#   endif

    return chr_count;
}

ME_API me_pid_t
ME_GetProcessParentEx(me_pid_t pid)
{
    me_pid_t ppid = (me_pid_t)ME_BAD;

    if (pid == (me_pid_t)ME_BAD)
        return ppid;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &entry))
            {
                do
                {
                    if (entry.th32ProcessID == pid)
                    {
                        ppid = (me_pid_t)entry.th32ParentProcessID;
                        break;
                    }
                } while(Process32Next(hSnap, &entry));
            }

            CloseHandle(hSnap);
        }
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_tchar_t *status_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t status_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_status_file;

            ME_SNPRINTF(status_path, ME_ARRLEN(status_path) - 1,
                        ME_STR("/proc/%d/status"), pid);
            fd = open(status_path, O_RDONLY);
            if (fd == -1)
                return ppid;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_status_file = status_file;
                status_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(status_file[0])
                );

                if (old_status_file != (me_tchar_t *)ME_NULL)
                {
                    if (status_file)
                    {
                        ME_MEMCPY(
                            status_file, old_status_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(status_file[0])
                        );
                    }

                    ME_free(old_status_file);
                }

                if (!status_file)
                    return ppid;

                ME_MEMCPY(&status_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_status_file = status_file;
            status_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(status_file[0])
            );

            if (status_file)
            {
                ME_MEMCPY(status_file, old_status_file,
                          read_len * read_count);
                status_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_status_file);

            if (!status_file)
                return ppid;
        }

        {
            me_tchar_t *ppid_str;
            me_tchar_t match[] = ME_STR("PPid:\t");
            if ((ppid_str = ME_STRSTR(status_file,  ME_STR(match))))
            {
                ppid = (me_pid_t)ME_STRTOL(&ppid_str[ME_ARRLEN(match) - 1], NULL, 10);
            }

            else
            {
                ppid = (me_pid_t)ME_NULL;
            }
        }

        ME_free(status_file);
    }
#   endif

    return ppid;
}

ME_API me_pid_t
ME_GetProcessParent(me_void_t)
{
    me_pid_t ppid = (me_pid_t)ME_BAD;
#   if ME_OS == ME_OS_WIN
    {
        ppid = ME_GetProcessParentEx(ME_GetProcess());
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        ppid = (me_pid_t)getppid();
    }
#   endif

    return ppid;
}

/****************************************/

ME_API me_bool_t
ME_EnumModulesEx(me_pid_t   pid,
                 me_bool_t(*callback)(me_pid_t    pid,
                                      me_module_t mod,
                                      me_void_t  *arg,
                                      me_void_t  *reserved),
                 me_void_t *arg)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !callback)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_EnumModules2Ex(pid, callback, arg, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t maps_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_maps_file;

            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(maps_file[0])
                );

                if (old_maps_file != (me_tchar_t *)ME_NULL)
                {
                    if (maps_file)
                    {
                        ME_MEMCPY(
                            maps_file, old_maps_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(maps_file[0])
                        );
                    }

                    ME_free(old_maps_file);
                }

                if (!maps_file)
                    return ret;

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_maps_file = maps_file;
            maps_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(maps_file[0])
            );

            if (maps_file)
            {
                ME_MEMCPY(maps_file, old_maps_file,
                          read_len * read_count);
                maps_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_maps_file);

            if (!maps_file)
                return ret;
        }

        ret = ME_EnumModules2Ex(pid, callback, arg, (me_void_t *)maps_file);

        ME_free(maps_file);
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_EnumModules2Ex(me_pid_t   pid,
                  me_bool_t(*callback)(me_pid_t    pid,
                                       me_module_t mod,
                                       me_void_t  *arg,
                                       me_void_t  *reserved),
                  me_void_t *arg,
                  me_void_t *reserved)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !callback)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

        if (hSnap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 entry;
            entry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(hSnap, &entry))
            {
                do
                {
                    me_module_t mod;
                    mod.base = (me_address_t)entry.modBaseAddr;
                    mod.size = (me_size_t)entry.modBaseSize;
                    mod.end  = (me_address_t)(&((me_byte_t *)mod.base)[mod.size]);

                    if (callback(pid, mod, arg) == ME_FALSE)
                        break;
                } while (Module32Next(hSnap, &entry));

                ret = ME_TRUE;
            }
        }
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)reserved;

        if (!maps_file)
            return ret;

        {
            me_tchar_t *mod_path_str = maps_file;
            while ((mod_path_str = ME_STRCHR(mod_path_str, ME_STR('/'))))
            {
                me_tchar_t *base_addr_str = maps_file;
                me_tchar_t *end_addr_str;

                {
                    me_tchar_t *tmp;
                    me_tchar_t *mod_path;
                    me_size_t mod_path_len = ((me_uintptr_t)ME_STRCHR(
                        mod_path_str, ME_STR('\n')
                    ) - (me_uintptr_t)mod_path_str) / sizeof(me_tchar_t);

                    mod_path = ME_calloc(mod_path_len + 1, sizeof(me_tchar_t));
                    if (!mod_path)
                        break;
                    
                    ME_MEMCPY(mod_path,
                              mod_path_str,
                              mod_path_len * sizeof(mod_path[0]));

                    for (
                        tmp = maps_file;
                        (tmp = ME_STRCHR(tmp, ME_STR('\n'))) &&
                            (me_uintptr_t)tmp < (me_uintptr_t)mod_path_str;
                        tmp = &tmp[1], base_addr_str = tmp
                    );

                    for (
                        tmp = mod_path_str;
                        (tmp = ME_STRSTR(tmp, mod_path));
                        mod_path_str = tmp, tmp = &tmp[1]
                    );

                    ME_free(mod_path);

                    for (
                        tmp = maps_file;
                        (tmp = ME_STRCHR(tmp, ME_STR('\n'))) &&
                            (me_uintptr_t)tmp < (me_uintptr_t)mod_path_str;
                        tmp = &tmp[1], end_addr_str = tmp
                    );

                    end_addr_str = ME_STRCHR(end_addr_str, ME_STR('-'));
                    end_addr_str = &end_addr_str[1];

                    {
                        me_module_t mod;
                        mod.base = (me_address_t)ME_STRTOP(base_addr_str,
                                                           NULL,
                                                           16);
                        mod.end  = (me_address_t)ME_STRTOP(end_addr_str,
                                                           NULL,
                                                           16);
                        mod.size = (me_size_t)(
                            (me_uintptr_t)mod.end - (me_uintptr_t)mod.base
                        );

                        if (callback(pid, mod, arg, reserved) == ME_FALSE)
                            break;
                    }

                    mod_path_str = &mod_path_str[mod_path_len];
                }
            }

            ret = ME_TRUE;
        }
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_EnumModules(me_bool_t(*callback)(me_pid_t    pid,
                                    me_module_t mod,
                                    me_void_t  *arg,
                                    me_void_t  *reserved),
               me_void_t *arg)
{
    return ME_EnumModulesEx(ME_GetProcess(), callback, arg);
}

ME_API me_bool_t
ME_EnumModules2(me_bool_t(*callback)(me_pid_t    pid,
                                     me_module_t mod,
                                     me_void_t  *arg,
                                     me_void_t  *reserved),
                me_void_t *arg,
                me_void_t *reserved)
{
    return ME_EnumModules2Ex(ME_GetProcess(), callback, arg, reserved);
}

static me_bool_t
_ME_GetModuleExCallback(me_pid_t    pid,
                        me_module_t mod,
                        me_void_t  *arg,
                        me_void_t  *reserved)
{
    _ME_GetModuleExArgs_t *parg = (_ME_GetModuleExArgs_t *)arg;
    me_tchar_t   mod_path[ME_PATH_MAX] = { 0 };
    me_size_t    mod_path_len;
    me_size_t    mod_ref_len = ME_STRLEN(parg->mod_ref);

    if ((mod_path_len = ME_GetModulePath2Ex(pid, mod,
                                            mod_path, ME_ARRLEN(mod_path),
                                            reserved)))
    {
        if (mod_ref_len <= mod_path_len)
        {
            if (!ME_STRCMP(&mod_path[mod_path_len - mod_ref_len], 
                            parg->mod_ref))
            {
                *parg->pmod = mod;
                return ME_FALSE;
            }
        }
    }

    return ME_TRUE;
}

ME_API me_bool_t
ME_GetModuleEx(me_pid_t     pid,
               me_tstring_t mod_ref,
               me_module_t *pmod)
{
    me_bool_t ret = ME_FALSE;
    _ME_GetModuleExArgs_t arg;
    arg.pmod = pmod;
    arg.mod_ref = mod_ref;

    if (pid != (me_pid_t)ME_BAD && arg.mod_ref && arg.pmod)
    {
        ret = ME_EnumModulesEx(pid, 
                               _ME_GetModuleExCallback,
                               (me_void_t *)&arg);
    }

    return ret;
}

ME_API me_bool_t
ME_GetModule2Ex(me_pid_t     pid,
                me_tstring_t mod_ref,
                me_module_t *pmod,
                me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;
    _ME_GetModuleExArgs_t arg;
    arg.pmod = pmod;
    arg.mod_ref = mod_ref;

    if (pid != (me_pid_t)ME_BAD && arg.mod_ref && arg.pmod)
    {
        ret = ME_EnumModules2Ex(pid, 
                                _ME_GetModuleExCallback,
                                (me_void_t *)&arg,
                                reserved);
    }

    return ret;
}

ME_API me_bool_t
ME_GetModule(me_tstring_t mod_ref,
             me_module_t *pmod)
{
    return ME_GetModuleEx(ME_GetProcess(), mod_ref, pmod);
}

ME_API me_bool_t
ME_GetModule2(me_tstring_t mod_ref,
              me_module_t *pmod,
              me_void_t   *reserved)
{
    return ME_GetModule2Ex(ME_GetProcess(), mod_ref, pmod, reserved);
}

static me_bool_t
_ME_FindModuleExCallback(me_pid_t    pid,
                         me_module_t mod,
                         me_void_t  *arg,
                         me_void_t  *reserved)
{
    _ME_FindModuleExArgs_t *parg = (_ME_FindModuleExArgs_t *)arg;
    me_tchar_t mod_path[ME_PATH_MAX] = { 0 };
    if (ME_GetModulePath2Ex(pid, mod, mod_path,
                            ME_ARRLEN(mod_path), reserved))
    {
        if (ME_STRSTR(mod_path, parg->mod_ref))
        {
            *(parg->pmod) = mod;
            return ME_FALSE;
        }
    }

    return ME_TRUE;
}

ME_API me_bool_t
ME_FindModuleEx(me_pid_t     pid,
                me_tstring_t mod_ref,
                me_module_t *pmod)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !mod_ref || !pmod)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_FindModule2Ex(pid, mod_ref, pmod, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t maps_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_maps_file;

            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(maps_file[0])
                );

                if (old_maps_file != (me_tchar_t *)ME_NULL)
                {
                    if (maps_file)
                    {
                        ME_MEMCPY(
                            maps_file, old_maps_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(maps_file[0])
                        );
                    }

                    ME_free(old_maps_file);
                }

                if (!maps_file)
                    return ret;

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_maps_file = maps_file;
            maps_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(maps_file[0])
            );

            if (maps_file)
            {
                ME_MEMCPY(maps_file, old_maps_file,
                          read_len * read_count);
                maps_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_maps_file);

            if (!maps_file)
                return ret;
        }

        ret = ME_FindModule2Ex(pid, mod_ref, pmod, (me_void_t *)maps_file);

        ME_free(maps_file);
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif
    return ret;
}

ME_API me_bool_t
ME_FindModule2Ex(me_pid_t     pid,
                 me_tstring_t mod_ref,
                 me_module_t *pmod,
                 me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;
    _ME_FindModuleExArgs_t arg;

    arg.pmod = pmod;
    arg.mod_ref = mod_ref;

    if (pid == (me_pid_t)ME_BAD || !arg.mod_ref || !arg.pmod)
        return ret;

    ret = ME_EnumModules2Ex(pid,
                            _ME_FindModuleExCallback,
                            (me_void_t *)&arg,
                            reserved);
    
    return ret;
}

ME_API me_bool_t
ME_FindModule(me_tstring_t mod_ref,
              me_module_t *pmod)
{
    return ME_FindModuleEx(ME_GetProcess(), mod_ref, pmod);
}

ME_API me_bool_t
ME_FindModule2(me_tstring_t mod_ref,
               me_module_t *pmod,
               me_void_t   *reserved)
{
    return ME_FindModule2Ex(ME_GetProcess(), mod_ref, pmod, reserved);
}

ME_API me_size_t
ME_GetModulePathEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_path,
                   me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (pid == (me_pid_t)ME_BAD || !mod_path || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        chr_count = ME_GetModulePath2Ex(pid, mod, mod_path,
                                        max_len, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t maps_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_maps_file;

            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return chr_count;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(maps_file[0])
                );

                if (old_maps_file != (me_tchar_t *)ME_NULL)
                {
                    if (maps_file)
                    {
                        ME_MEMCPY(
                            maps_file, old_maps_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(maps_file[0])
                        );
                    }

                    ME_free(old_maps_file);
                }

                if (!maps_file)
                    return chr_count;

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_maps_file = maps_file;
            maps_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(maps_file[0])
            );

            if (maps_file)
            {
                ME_MEMCPY(maps_file, old_maps_file,
                          read_len * read_count);
                maps_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_maps_file);

            if (!maps_file)
                return chr_count;
        }

        chr_count = ME_GetModulePath2Ex(pid, mod, mod_path,
                                        max_len, (me_void_t *)maps_file);

        ME_free(maps_file);
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetModulePath2Ex(me_pid_t    pid,
                    me_module_t mod,
                    me_tchar_t *mod_path,
                    me_size_t   max_len,
                    me_void_t  *reserved)
{
    me_size_t chr_count = 0;

    if (pid == (me_pid_t)ME_BAD || !mod_path || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

        if (hSnap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 entry;
            entry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(hSnap, &entry))
            {
                do
                {
                    if ((me_address_t)entry.modBaseAddr == mod.base)
                    {
                        chr_count = ME_STRLEN(entry.szExePath);
                        if (chr_count > max_len)
                            chr_count = max_len - 1;
                        ME_MEMCPY(mod_path,
                                  entry.szExePath,
                                  chr_count * sizeof(me_tchar_t));
                        mod_path[chr_count] = ME_STR('\00');
                        break;
                    }
                } while (Module32Next(hSnap, &entry));
            }
        }
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)reserved;
        
        if (!maps_file)
            return chr_count;

        {
            me_tchar_t base_addr_str[64] = { 0 };
#           if ME_ARCH_SIZE == 32
            me_tchar_t fmt[] = "%lx";
#           elif ME_ARCH_SIZE == 64
            me_tchar_t fmt[] = "%llx";
#           endif
            me_tchar_t *mod_path_str;

            ME_SNPRINTF(base_addr_str,
                        ME_ARRLEN(base_addr_str),
                        fmt,
                        mod.base);
            
            if ((mod_path_str = ME_STRSTR(maps_file, base_addr_str)) &&
                (mod_path_str = ME_STRCHR(mod_path_str, ME_STR('/'))))
            {
                me_tchar_t *mod_path_end = ME_STRCHR(mod_path_str,
                                                     ME_STR('\n'));
                chr_count = (me_size_t)(
                    (
                        (me_uintptr_t)mod_path_end - 
                            (me_uintptr_t)mod_path_str
                    ) / sizeof(me_tchar_t)
                );

                if (chr_count > max_len)
                    chr_count = max_len - 1;
                
                ME_MEMCPY(mod_path,
                          mod_path_str,
                          chr_count * sizeof(me_tchar_t));
                
                mod_path[chr_count] = ME_STR('\00');
            }
        }
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetModulePath(me_module_t mod,
                 me_tchar_t *mod_path,
                 me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (!mod_path || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        chr_count = ME_GetModulePath2(mod, mod_path, 
                                      max_len, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        chr_count = ME_GetModulePathEx(ME_GetProcess(), mod, 
                                       mod_path, max_len);
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetModulePath2(me_module_t mod,
                  me_tchar_t *mod_path,
                  me_size_t   max_len,
                  me_void_t  *reserved)
{
    me_size_t chr_count = 0;

    if (!mod_path || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        HMODULE hModule = (HMODULE)NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          (LPTSTR)mod.base,
                          &hModule);
        if (!hModule)
            return chr_count;
        GetModuleFileName(hModule, mod_path, max_len);
        mod_path[max_len - 1] = ME_STR('\00');
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        chr_count = ME_GetModulePath2Ex(ME_GetProcess(), mod, mod_path,
                                        max_len, reserved);
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetModuleNameEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_name,
                   me_size_t   max_len)
{
    me_size_t chr_count = 0;

    if (pid == (me_pid_t)ME_BAD || !mod_name || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        chr_count = ME_GetModuleName2Ex(pid, mod, mod_name,
                                        max_len, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_tchar_t mod_path[ME_PATH_MAX] = { 0 };
        if (ME_GetModulePathEx(pid, mod, mod_path, ME_ARRLEN(mod_path)))
        {
            me_tchar_t path_chr;
            me_tchar_t *tmp;
            me_tchar_t *file_str;

#           if ME_OS == ME_OS_WIN
            path_chr = ME_STR('\\');
#           elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
            path_chr = ME_STR('/');
#           endif

            for (tmp = mod_path;
                    (tmp = ME_STRCHR(tmp, path_chr));
                    tmp = &tmp[1], file_str = tmp);

            chr_count = ME_STRLEN(file_str);
            if (chr_count > max_len)
                chr_count = max_len;

            ME_MEMCPY((void *)mod_name, (void *)file_str,
                        chr_count * sizeof(mod_name[0]));
        }
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetModuleName2Ex(me_pid_t    pid,
                    me_module_t mod,
                    me_tchar_t *mod_name,
                    me_size_t   max_len,
                    me_void_t  *reserved)
{
    me_size_t chr_count = 0;

    if (pid == (me_pid_t)ME_BAD || !mod_name || max_len == 0)
        return chr_count;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

        if (hSnap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 entry;
            entry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(hSnap, &entry))
            {
                do
                {
                    if ((me_address_t)entry.modBaseAddr == mod.base)
                    {
                        chr_count = ME_STRLEN(entry.szModule);
                        if (chr_count > max_len)
                            chr_count = max_len - 1;
                        ME_MEMCPY(mod_name,
                                  entry.szModule,
                                  chr_count * sizeof(me_tchar_t));
                        mod_name[chr_count] = ME_STR('\00');
                        break;
                    }
                } while (Module32Next(hSnap, &entry));
            }
        }
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_tchar_t mod_path[ME_PATH_MAX] = { 0 };
        if (ME_GetModulePath2Ex(pid, mod, mod_path, 
                                ME_ARRLEN(mod_path), reserved))
        {
            me_tchar_t path_chr;
            me_tchar_t *tmp;
            me_tchar_t *file_str;

#           if ME_OS == ME_OS_WIN
            path_chr = ME_STR('\\');
#           elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
            path_chr = ME_STR('/');
#           endif

            for (tmp = mod_path;
                    (tmp = ME_STRCHR(tmp, path_chr));
                    tmp = &tmp[1], file_str = tmp);

            chr_count = ME_STRLEN(file_str);
            if (chr_count > max_len)
                chr_count = max_len;

            ME_MEMCPY((void *)mod_name, (void *)file_str,
                        chr_count * sizeof(mod_name[0]));
        }
    }
#   endif

    return chr_count;
}

ME_API me_size_t
ME_GetModuleName(me_module_t mod,
                 me_tchar_t *mod_name,
                 me_size_t   max_len)
{
    me_size_t chr_count = 0;
    me_tchar_t mod_path[ME_PATH_MAX] = { 0 };

    if (!mod_name || max_len == 0)
        return chr_count;

    if (ME_GetModulePath(mod, mod_path, ME_ARRLEN(mod_path)))
    {
        me_tchar_t path_chr;
        me_tchar_t *tmp;
        me_tchar_t *file_str;

#       if ME_OS == ME_OS_WIN
        path_chr = ME_STR('\\');
#       elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
        path_chr = ME_STR('/');
#       endif

        for (tmp = mod_path;
                (tmp = ME_STRCHR(tmp, path_chr));
                tmp = &tmp[1], file_str = tmp);

        chr_count = ME_STRLEN(file_str);
        if (chr_count > max_len)
            chr_count = max_len;

        ME_MEMCPY((void *)mod_name, (void *)file_str,
                    chr_count * sizeof(mod_name[0]));
    }

    return chr_count;
}

ME_API me_size_t
ME_GetModuleName2(me_module_t mod,
                  me_tchar_t *mod_name,
                  me_size_t   max_len,
                  me_void_t  *reserved)
{
    me_size_t chr_count = 0;
    me_tchar_t mod_path[ME_PATH_MAX] = { 0 };

    if (!mod_name || max_len == 0)
        return chr_count;

    if (ME_GetModulePath2(mod, mod_path, ME_ARRLEN(mod_path), reserved))
    {
        me_tchar_t path_chr;
        me_tchar_t *tmp;
        me_tchar_t *file_str;

#       if ME_OS == ME_OS_WIN
        path_chr = ME_STR('\\');
#       elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
        path_chr = ME_STR('/');
#       endif

        for (tmp = mod_path;
                (tmp = ME_STRCHR(tmp, path_chr));
                tmp = &tmp[1], file_str = tmp);

        chr_count = ME_STRLEN(file_str);
        if (chr_count > max_len)
            chr_count = max_len;

        ME_MEMCPY((void *)mod_name, (void *)file_str,
                    chr_count * sizeof(mod_name[0]));
    }

    return chr_count;
}

ME_API me_bool_t
ME_LoadModuleEx(me_pid_t     pid,
                me_tstring_t path,
                me_module_t *pmod)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !path)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_LoadModule2Ex(pid, path, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int mode = RTLD_LAZY;
        me_tchar_t *maps_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t maps_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_maps_file;

            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(maps_file[0])
                );

                if (old_maps_file != (me_tchar_t *)ME_NULL)
                {
                    if (maps_file)
                    {
                        ME_MEMCPY(
                            maps_file, old_maps_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(maps_file[0])
                        );
                    }

                    ME_free(old_maps_file);
                }

                if (!maps_file)
                    return ret;

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_maps_file = maps_file;
            maps_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(maps_file[0])
            );

            if (maps_file)
            {
                ME_MEMCPY(maps_file, old_maps_file,
                          read_len * read_count);
                maps_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_maps_file);

            if (!maps_file)
                return ret;
        }

        ret = ME_LoadModule2Ex(pid, path, (me_void_t *)&mode, maps_file);

        if (pmod)
        {
            ME_GetModuleEx(pid, path, pmod);
        }

        ME_free(maps_file);
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_LoadModule2Ex(me_pid_t     pid,
                 me_tstring_t path,
                 me_void_t   *reserved,
                 ...)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !path)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        me_address_t path_addr;
        me_size_t path_size = (ME_STRLEN(path) + 1) * sizeof(path[0]);
        path_addr = ME_AllocateMemoryEx(pid, path_size, ME_PROT_RW);

        if (!path_addr)
            return ret;

        if (ME_WriteMemoryEx(pid, path_addr, (me_byte_t *)path, path_size))
        {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

            if (hProcess)
            {
                HANDLE hThread = (HANDLE)CreateRemoteThread(
                    hProcess, NULL, 0, 
                    (LPTHREAD_START_ROUTINE)LoadLibrary, path_addr, 0, NULL
                );

                if (hThread)
                {
                    WaitForSingleObject(hThread, INFINITE);
                    CloseHandle(hThread);
                    ret = ME_TRUE;
                }

                CloseHandle(hProcess);
            }
        }

        ME_FreeMemoryEx(pid, path_addr, path_size);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_tchar_t *maps_file;
        int *mode = (int *)reserved;
        me_address_t dlopen_ex;
        me_address_t inj_addr;
        me_size_t inj_size;
        me_address_t path_addr;
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        me_byte_t code[] =
        {
            0xFF, 0xD0, /* call rax */
            0xCC        /* int3 */
        };
#       else
        me_byte_t code[] =
        {
            0x51,       /* push ecx */
            0x53,       /* push ebx */
            0xFF, 0xD0, /* call eax */
            0xCC,       /* int3 */
        };
#       endif
#       endif

        {
            va_list va;
            va_start(va, reserved);
            maps_file = va_arg(va, me_tchar_t *);
            va_end(va);
        }

        if (!maps_file)
            return ret;

        {
            me_module_t libc_mod;
            me_tchar_t  libc_path[ME_PATH_MAX];
            void *libc_handle;

            if (!ME_FindModule2Ex(pid, ME_STR("/libc-"),
                                  &libc_mod, maps_file) ||
                !ME_FindModule2Ex(pid, ME_STR("/libc."),
                                  &libc_mod, maps_file))
            {
                return ret;
            }

            if (!ME_GetModulePath2Ex(pid, libc_mod, libc_path,
                                     ME_ARRLEN(libc_path), maps_file))
            {
                return ret;
            }

            libc_handle = dlopen(libc_path, RTLD_NOW);

            if (!libc_handle)
                return ret;

            {
                Dl_info info;
                me_address_t dlopen_in = (me_address_t)(
                    dlsym(libc_handle, "__libc_dlopen_mode")
                );

                if (!dlopen_in)
                    return ret;

                if (!dladdr(dlopen_in, &info))
                    return ret;

                dlopen_ex = (me_address_t)(
                    (me_uintptr_t)libc_mod.base +
                    ((me_uintptr_t)dlopen_in - (me_uintptr_t)info.dli_fbase)
                );
            }

            dlclose(libc_handle);
        }

        {
            me_bool_t check;
            me_size_t path_size = (ME_STRLEN(path) + 1) * sizeof(path[0]);
            inj_size = sizeof(code) + path_size;

            inj_addr = ME_AllocateMemoryEx(pid, inj_size, ME_PROT_XRW);

            if (inj_addr == (me_address_t)ME_BAD)
                return ret;

            path_addr = (me_address_t)(&((me_byte_t *)inj_addr)[sizeof(code)]);

            check = ME_WriteMemoryEx(pid, inj_addr, code, sizeof(code)) ?
                ME_TRUE : ME_FALSE;
            check &= ME_WriteMemoryEx(pid, path_addr,
                                      (me_byte_t *)path, path_size) ?
                ME_TRUE : ME_FALSE;

            if (!check)
                goto L_FREE;
        }

        {
            struct user_regs_struct regs, old_regs;
            me_bool_t debugged;

            debugged = ME_GetStateDbg(pid);

            if (!debugged)
            {
                me_bool_t check;
                check = ME_AttachDbg(pid);
                check &= ME_WaitDbg();
                if (!check)
                    return ret;
            }

            ME_GetRegsDbg(pid, &old_regs);
            regs = old_regs;
            
#           if ME_ARCH == ME_ARCH_X86
#           if ME_ARCH_SIZE == 64
            ME_WriteRegDbg((me_uintptr_t)dlopen_ex, ME_REGID_RAX, &regs);
            ME_WriteRegDbg((me_uintptr_t)path_addr, ME_REGID_RDI, &regs);
            ME_WriteRegDbg((me_uintptr_t)(*mode),   ME_REGID_RSI, &regs);
            ME_WriteRegDbg((me_uintptr_t)inj_addr,  ME_REGID_RIP, &regs);
#           else
            ME_WriteRegDbg((me_uintptr_t)dlopen_ex, ME_REGID_EAX, &regs);
            ME_WriteRegDbg((me_uintptr_t)path_addr, ME_REGID_EBX, &regs);
            ME_WriteRegDbg((me_uintptr_t)(*mode),   ME_REGID_ECX, &regs);
            ME_WriteRegDbg((me_uintptr_t)inj_addr,  ME_REGID_EIP, &regs);
#           endif
#           endif

            ME_SetRegsDbg(pid, regs);
            ME_ContinueDbg(pid);
            ME_WaitProcessDbg(pid);
            ME_SetRegsDbg(pid, old_regs);

            if (!debugged)
                ME_DetachDbg(pid);
        }

    L_FREE:
        ME_FreeMemoryEx(pid, inj_addr, inj_size);

        ret = ME_TRUE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_LoadModule(me_tstring_t path,
              me_module_t *pmod)
{
    me_bool_t ret = ME_FALSE;

    if (!path)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_LoadModule2(path, pmod, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int mode = RTLD_LAZY;
        ret = ME_LoadModule2(path, (me_void_t *)&mode);

        if (pmod)
            ME_GetModule(path, pmod);
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_LoadModule2(me_tstring_t path,
               me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;

    if (!path)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = (LoadLibrary(path) != NULL) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int *pmode = (int *)reserved;
        ret = dlopen(path, *pmode) ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_UnloadModuleEx(me_pid_t    pid,
                  me_module_t mod)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_UnloadModule2Ex(pid, mod, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t maps_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_maps_file;

            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(maps_file[0])
                );

                if (old_maps_file != (me_tchar_t *)ME_NULL)
                {
                    if (maps_file)
                    {
                        ME_MEMCPY(
                            maps_file, old_maps_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(maps_file[0])
                        );
                    }

                    ME_free(old_maps_file);
                }

                if (!maps_file)
                    return ret;

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_maps_file = maps_file;
            maps_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(maps_file[0])
            );

            if (maps_file)
            {
                ME_MEMCPY(maps_file, old_maps_file,
                          read_len * read_count);
                maps_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_maps_file);

            if (!maps_file)
                return ret;
        }

        ret = ME_UnloadModule2Ex(pid, mod, (me_void_t *)maps_file);

        ME_free(maps_file);
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_UnloadModule2Ex(me_pid_t    pid,
                   me_module_t mod,
                   me_void_t  *reserved)
{
    /* WIP */

    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)reserved;
        me_address_t dlclose_ex;
        me_address_t inj_addr;
        me_size_t inj_size;
        void *mod_handle = (void *)NULL; /* TODO: Get Module Handle */
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        me_byte_t code[] =
        {
            0xFF, 0xD0, /* call rax */
            0xCC        /* int3 */
        };
#       else
        me_byte_t code[] =
        {
            0x53,       /* push ebx */
            0xFF, 0xD0, /* call eax */
            0xCC,       /* int3 */
        };
#       endif
#       endif

        if (!maps_file)
            return ret;

        {
            me_module_t libc_mod;
            me_tchar_t  libc_path[ME_PATH_MAX];
            void *libc_handle;

            if (!ME_FindModule2Ex(pid, ME_STR("/libc-"),
                                  &libc_mod, maps_file) ||
                !ME_FindModule2Ex(pid, ME_STR("/libc."),
                                  &libc_mod, maps_file))
            {
                return ret;
            }

            if (!ME_GetModulePath2Ex(pid, libc_mod, libc_path,
                                     ME_ARRLEN(libc_path), maps_file))
            {
                return ret;
            }

            libc_handle = dlopen(libc_path, RTLD_NOW);

            if (!libc_handle)
                return ret;

            {
                Dl_info info;
                me_address_t dlclose_in = (me_address_t)(
                    dlsym(libc_handle, "__libc_dlclose")
                );

                if (!dlclose_in)
                    return ret;

                if (!dladdr(dlclose_in, &info))
                    return ret;

                dlclose_ex = (me_address_t)(
                    (me_uintptr_t)libc_mod.base +
                    ((me_uintptr_t)dlclose_in - (me_uintptr_t)info.dli_fbase)
                );
            }

            dlclose(libc_handle);
        }

        {
            me_bool_t check;

            inj_size = sizeof(code);
            inj_addr = ME_AllocateMemoryEx(pid, inj_size, ME_PROT_XRW);

            if (inj_addr == (me_address_t)ME_BAD)
                return ret;

            check = ME_WriteMemoryEx(pid, inj_addr, code, sizeof(code)) ?
                ME_TRUE : ME_FALSE;

            if (!check)
                goto L_FREE;
        }

        {
            struct user_regs_struct regs, old_regs;
            me_bool_t debugged;

            debugged = ME_GetStateDbg(pid);

            if (!debugged)
            {
                me_bool_t check;
                check = ME_AttachDbg(pid);
                check &= ME_WaitDbg();
                if (!check)
                    return ret;
            }

            ME_GetRegsDbg(pid, &old_regs);
            regs = old_regs;
            
#           if ME_ARCH == ME_ARCH_X86
#           if ME_ARCH_SIZE == 64
            ME_WriteRegDbg((me_uintptr_t)dlclose_ex, ME_REGID_RAX, &regs);
            ME_WriteRegDbg((me_uintptr_t)mod_handle, ME_REGID_RDI, &regs);
            ME_WriteRegDbg((me_uintptr_t)inj_addr,   ME_REGID_RIP, &regs);
#           else
            ME_WriteRegDbg((me_uintptr_t)dlclose_ex, ME_REGID_EAX, &regs);
            ME_WriteRegDbg((me_uintptr_t)mod_handle, ME_REGID_EBX, &regs);
            ME_WriteRegDbg((me_uintptr_t)inj_addr,   ME_REGID_EIP, &regs);
#           endif
#           endif

            ME_SetRegsDbg(pid, regs);
            ME_ContinueDbg(pid);
            ME_WaitProcessDbg(pid);
            ME_SetRegsDbg(pid, old_regs);

            if (!debugged)
                ME_DetachDbg(pid);
        }

    L_FREE:
        ME_FreeMemoryEx(pid, inj_addr, inj_size);

        ret = ME_TRUE;
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_UnloadModule(me_module_t mod)
{
    me_bool_t ret = ME_FALSE;
#   if ME_OS == ME_OS_WIN
    {
        HMODULE hModule = (HMODULE)NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                          (LPTSTR)mod.base,
                          &hModule);
        if (!hModule)
            return chr_count;
        ret = FreeLibrary(hModule) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_tchar_t mod_path[ME_PATH_MAX] = { 0 };

        if (ME_GetModulePath(mod, mod_path, ME_ARRLEN(mod_path)))
        {
            void *handle = dlopen(mod_path, RTLD_NOW | RTLD_NOLOAD);

            if (handle)
            {
                ret = !dlclose(handle) ? ME_TRUE : ME_FALSE;
            }
        }
    }
#   endif

    return ret;
}

/****************************************/

ME_API me_bool_t
ME_EnumPagesEx(me_pid_t   pid,
               me_bool_t(*callback)(me_page_t  page,
                                    me_void_t *arg),
               me_void_t *arg)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !callback)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_EnumPages2Ex(pid, callback, arg, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t maps_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_maps_file;

            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(maps_file[0])
                );

                if (old_maps_file != (me_tchar_t *)ME_NULL)
                {
                    if (maps_file)
                    {
                        ME_MEMCPY(
                            maps_file, old_maps_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(maps_file[0])
                        );
                    }

                    ME_free(old_maps_file);
                }

                if (!maps_file)
                    return ret;

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_maps_file = maps_file;
            maps_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(maps_file[0])
            );

            if (maps_file)
            {
                ME_MEMCPY(maps_file, old_maps_file,
                          read_len * read_count);
                maps_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_maps_file);

            if (!maps_file)
                return ret;
        }

        ret = ME_EnumPages2Ex(pid, callback, arg, (me_void_t *)maps_file);

        ME_free(maps_file);
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_EnumPages2Ex(me_pid_t   pid,
                me_bool_t(*callback)(me_page_t  page,
                                     me_void_t *arg),
                me_void_t *arg,
                me_void_t *reserved)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !callback)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_tchar_t *maps_file = (me_tchar_t *)reserved;

        if (!maps_file)
            return ret;

        {
            me_tchar_t *page_base_ptr;
            
            for (page_base_ptr = maps_file;
                 page_base_ptr;
                 page_base_ptr = ME_STRCHR(&page_base_ptr[1], ME_STR('\n')))
            {
                me_page_t page;
                me_tchar_t *page_end_ptr;
                me_tchar_t *page_info_ptr;

                page_end_ptr = ME_STRCHR(page_base_ptr, ME_STR('-'));
                page_end_ptr = &page_end_ptr[1];

                page.base = (me_address_t)ME_STRTOP(&page_base_ptr[1],
                                                    NULL,
                                                    16);
                
                page.end  = (me_address_t)ME_STRTOP(page_end_ptr, NULL, 16);
                page.size = (me_size_t)((me_uintptr_t)page.end -
                                        (me_uintptr_t)page.base);

                page_info_ptr = ME_STRCHR(page_end_ptr, ME_STR(' '));
                page_info_ptr = &page_info_ptr[1];

                page.prot  = 0;
                page.flags = 0;

                {
                    me_tchar_t *c;
                    for (c = page_info_ptr; c != &page_info_ptr[4]; c = &c[1])
                    {
                        switch (*c)
                        {
                        case ME_STR('r'):
                            page.prot |= PROT_READ;
                            break;
                        case ME_STR('w'):
                            page.prot |= PROT_WRITE;
                            break;
                        case ME_STR('x'):
                            page.prot |= PROT_EXEC;
                            break;
                        case ME_STR('s'):
                            page.flags = MAP_SHARED;
                            break;
                        case ME_STR('p'):
                            page.flags = MAP_PRIVATE;
                            break;
                        }
                    }
                }

                if (callback(page, arg) == ME_FALSE)
                    break;
            }
        }
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_EnumPages(me_bool_t(*callback)(me_page_t  page,
                                  me_void_t *arg),
             me_void_t *arg)
{
    return ME_EnumPagesEx(ME_GetProcess(), callback, arg);
}

ME_API me_bool_t
ME_EnumPages2(me_bool_t(*callback)(me_page_t  page,
                                   me_void_t *arg),
              me_void_t *arg,
              me_void_t *reserved)
{
    return ME_EnumPages2Ex(ME_GetProcess(), callback, arg, reserved);
}

static me_bool_t
_ME_GetPageExCallback(me_page_t  page,
                      me_void_t *arg)
{
    _ME_GetPageExArgs_t *parg = (_ME_GetPageExArgs_t *)arg;
    me_uintptr_t page_base = (me_uintptr_t)page.base;
    me_uintptr_t page_end  = (me_uintptr_t)page.end;
    me_uintptr_t addr = (me_uintptr_t)parg->addr;

    if (addr >= page_base && addr < page_end)
    {
        *parg->ppage = page;
        return ME_FALSE;
    }

    return ME_TRUE;
}

ME_API me_bool_t
ME_GetPageEx(me_pid_t     pid,
             me_address_t addr,
             me_page_t   *ppage)
{
    me_bool_t ret = ME_FALSE;
    _ME_GetPageExArgs_t arg;
    arg.addr = addr;
    arg.ppage = ppage;

    if (pid == (me_pid_t)ME_BAD || !arg.ppage)
        return ret;

    ret = ME_EnumPagesEx(pid, _ME_GetPageExCallback, (me_void_t *)&arg);

    return ret;
}

ME_API me_bool_t
ME_GetPage2Ex(me_pid_t     pid,
              me_address_t addr,
              me_page_t   *ppage,
              me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;
    _ME_GetPageExArgs_t arg;
    arg.addr = addr;
    arg.ppage = ppage;

    if (pid == (me_pid_t)ME_BAD || !arg.ppage)
        return ret;

    ret = ME_EnumPages2Ex(pid, _ME_GetPageExCallback,
                          (me_void_t *)&arg, reserved);

    return ret;
}

ME_API me_bool_t
ME_GetPage(me_address_t addr,
           me_page_t   *ppage)
{
    return ME_GetPageEx(ME_GetProcess(), addr, ppage);
}

ME_API me_bool_t
ME_GetPage2(me_address_t addr,
            me_page_t   *ppage,
            me_void_t   *reserved)
{
    return ME_GetPage2Ex(ME_GetProcess(), addr, ppage, reserved);
}

/****************************************/

ME_API me_size_t
ME_ReadMemoryEx(me_pid_t     pid,
                me_address_t src,
                me_byte_t   *dst,
                me_size_t    size)
{
    me_size_t byte_count = 0;

    if (pid == (me_pid_t)ME_BAD || !dst || size == 0)
        return byte_count;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProcess)
            return byte_count;

        byte_count = (me_size_t)ReadProcessMemory(hProcess, src, dst, size, NULL);
        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        struct iovec iosrc = { 0 };
        struct iovec iodst = { 0 };
        iodst.iov_base = dst;
        iodst.iov_len  = size;
        iosrc.iov_base = src;
        iosrc.iov_len  = size;
        byte_count = (me_size_t)process_vm_readv(pid, &iodst, 1, &iosrc, 1, 0);

        if (byte_count == (me_size_t)-1)
            byte_count = 0;
    }
#   elif ME_OS == ME_OS_BSD
    {
        int fd = -1;

        {
            me_tchar_t mem_path[64] = { 0 };
            ME_SNPRINTF(mem_path, sizeof(mem_path) - sizeof(me_tchar_t),
                        ME_STR("/proc/%d/mem"), pid);
            fd = open(mem_path, O_RDONLY);
        }

        if (fd == -1)
            return byte_count;

        byte_count = (me_size_t)pread(fd, dst, size, (off_t)src);
        close(fd);

        if (byte_count == (me_size_t)-1)
            byte_count = 0;
    }
#   endif

    return byte_count;
}

ME_API me_size_t
ME_ReadMemory(me_address_t src,
              me_byte_t   *dst,
              me_size_t    size)
{
    me_size_t i;
    for (i = 0; i < size; ++i)
        dst[i] = ((me_byte_t *)src)[i];

    return i;
}

ME_API me_size_t
ME_WriteMemoryEx(me_pid_t     pid,
                 me_address_t dst,
                 me_byte_t   *src,
                 me_size_t    size)
{
    me_size_t byte_count = 0;

    if (pid == (me_pid_t)ME_BAD || !src || size == 0)
        return byte_count;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProcess)
            return byte_count;

        byte_count = (me_size_t)WriteProcessMemory(hProcess, dst, src, size, NULL);
        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        struct iovec iosrc = { 0 };
        struct iovec iodst = { 0 };
        iosrc.iov_base = src;
        iosrc.iov_len = size;
        iodst.iov_base = dst;
        iodst.iov_len = size;
        byte_count = (me_size_t)process_vm_writev(pid, &iosrc, 1, &iodst, 1, 0);

        if (byte_count == (me_size_t)-1)
            byte_count = 0;
    }
#   elif ME_OS == ME_OS_BSD
    {
        int fd = -1;

        {
            me_tchar_t mem_path[64] = { 0 };
            ME_SNPRINTF(mem_path, sizeof(mem_path) - sizeof(me_tchar_t),
                        ME_STR("/proc/%d/mem"), pid);
            fd = open(mem_path, O_RDONLY);
        }

        if (fd == -1)
            return byte_count;

        byte_count = (me_size_t)pwrite(fd, src, size, (off_t)dst);
        close(fd);

        if (byte_count == (me_size_t)-1)
            byte_count = 0;
    }
#   endif

    return byte_count;
}

ME_API me_size_t
ME_WriteMemory(me_address_t dst,
               me_byte_t   *src,
               me_size_t    size)
{
    me_size_t i;
    for (i = 0; i < size; ++i)
        ((me_byte_t *)dst)[i] = src[i];

    return i;
}

ME_API me_bool_t
ME_ProtectMemoryEx(me_pid_t     pid,
                   me_address_t addr,
                   me_size_t    size,
                   me_prot_t    prot,
                   me_prot_t   *old_prot)
{
    me_bool_t ret = ME_FALSE;
    me_prot_t old_protection = 0;

    if (pid == (me_pid_t)ME_BAD || size == 0)
        return ret;
    
#   if ME_OS == ME_OS_WIN
    {
        ret = ME_ProtectMemory2Ex(pid, addr, size, prot, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_page_t page;
        me_int_t  nsyscall = -1;
#       if ME_OS == ME_OS_LINUX
        nsyscall = __NR_mprotect;
#       elif ME_OS == ME_OS_BSD
        nsyscall = SYS_mprotect;
#       endif

        if (!ME_GetPageEx(pid, addr, &page))
            return ret;

        old_protection = page.prot;

        ret = (
            !ME_SyscallEx(pid,
                          nsyscall,
                          (me_void_t *)page.base,
                          (me_void_t *)(me_uintptr_t)size,
                          (me_void_t *)(me_uintptr_t)prot,
                          ME_NULLPTR,
                          ME_NULLPTR,
                          ME_NULLPTR)
        ) ? ME_TRUE : ME_FALSE;
    }
#   endif

    if (old_prot)
        *old_prot = old_protection;

    return ret;
}

ME_API me_bool_t
ME_ProtectMemory2Ex(me_pid_t     pid,
                    me_address_t addr,
                    me_size_t    size,
                    me_prot_t    prot,
                    me_prot_t   *old_prot,
                    me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;
    me_prot_t old_protection = 0;

    if (pid == (me_pid_t)ME_BAD || size == 0)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProcess)
            return ret;

        ret = VirtualProtectEx(hProcess, addr, size,
                               prot, &old_protection) ? ME_TRUE : ME_FALSE;

        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_page_t page;
        me_int_t  nsyscall = -1;
#       if ME_OS == ME_OS_LINUX
        nsyscall = __NR_mprotect;
#       elif ME_OS == ME_OS_BSD
        nsyscall = SYS_mprotect;
#       endif

        if (!ME_GetPage2Ex(pid, addr, &page, reserved))
            return ret;

        old_protection = page.prot;

        ret = (
            !ME_SyscallEx(pid,
                          nsyscall,
                          (me_void_t *)page.base,
                          (me_void_t *)(me_uintptr_t)size,
                          (me_void_t *)(me_uintptr_t)prot,
                          ME_NULLPTR,
                          ME_NULLPTR,
                          ME_NULLPTR)
        ) ? ME_TRUE : ME_FALSE;
    }
#   endif

    if (old_prot)
        *old_prot = old_protection;

    return ret;
}

ME_API me_bool_t
ME_ProtectMemory(me_address_t addr,
                 me_size_t    size,
                 me_prot_t    prot,
                 me_prot_t   *old_prot)
{
    me_bool_t ret = ME_FALSE;
    me_prot_t old_protection = 0;

    if (size == 0)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_ProtectMemory2(addr, size, prot,
                                old_prot, ME_NULLPTR);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_page_t page;

        if (!ME_GetPage(addr, &page))
            return ret;

        ret = !mprotect(page.base, size, prot) ? ME_TRUE : ME_FALSE;
    }
#   endif

    if (old_prot)
        *old_prot = old_protection;
    
    return ret;
}

ME_API me_bool_t
ME_ProtectMemory2(me_address_t addr,
                  me_size_t    size,
                  me_prot_t    prot,
                  me_prot_t   *old_prot,
                  me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;
    me_prot_t old_protection = 0;

    if (size == 0)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = VirtualProtect(addr, size,
                             prot, old_protection) != 0 ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_page_t page;
        
        if (!ME_GetPage2(addr, &page, reserved))
            return ret;

        ret = !mprotect(page.base, size, prot) ? ME_TRUE : ME_FALSE;
    }
#   endif

    if (old_prot)
        *old_prot = old_protection;
    
    return ret;
}

ME_API me_address_t
ME_AllocateMemoryEx(me_pid_t   pid,
                    me_size_t  size,
                    me_prot_t  prot)
{
    me_address_t alloc = (me_address_t)ME_BAD;

    if (pid == (me_pid_t)ME_BAD)
        return alloc;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProcess)
            return alloc;

        alloc = (me_address_t)VirtualAllocEx(hProcess, NULL, 0,
                                             ME_ALLOC_DEFAULT, prot);

        if (!alloc)
            alloc = (me_address_t)ME_BAD;

        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_int_t nsyscall = -1;
#       if ME_OS == ME_OS_LINUX
#       if ME_ARCH_SIZE == 64
        nsyscall = __NR_mmap;
#       else
        nsyscall = __NR_mmap2;
#       endif
#       elif ME_OS == ME_OS_BSD
        nsyscall = SYS_mmap;
#       endif

        alloc = (me_address_t)ME_SyscallEx(pid,
                                           nsyscall,
                                           (me_void_t *)0,
                                           (me_void_t *)(me_uintptr_t)size,
                                           (me_void_t *)(me_uintptr_t)prot,
                                           (me_void_t *)(MAP_PRIVATE |
                                                         MAP_ANON),
                                           (me_void_t *)-1,
                                           (me_void_t *)0);

        if (alloc == (me_address_t)MAP_FAILED ||
            (me_uintptr_t)alloc >= (me_uintptr_t)-4096)
        {
            alloc = (me_address_t)ME_BAD;
        }
    }
#   endif

    return alloc;
}

ME_API me_address_t
ME_AllocateMemory(me_size_t  size,
                  me_prot_t  prot)
{
    me_address_t alloc = (me_address_t)ME_BAD;
#   if ME_OS == ME_OS_WIN
    {
        alloc = (me_address_t)VirtualAlloc(NULL,
                                           0,
                                           MEM_COMMIT | MEM_RESERVE,
                                           prot);
        
        if (!alloc)
            alloc = (me_address_t)ME_BAD;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        alloc = (me_address_t)mmap(NULL,
                                   size,
                                   prot,
                                   MAP_PRIVATE | MAP_ANON,
                                   -1,
                                   0);

        if (alloc == (me_address_t)MAP_FAILED)
            alloc = (me_address_t)ME_BAD;
    }
#   endif

    return alloc;
}

ME_API me_bool_t
ME_FreeMemoryEx(me_pid_t     pid,
                me_address_t addr,
                me_size_t    size)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProcess)
            return ret;

        ret = (
            VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE)
        ) ? ME_TRUE : ME_FALSE;

        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_int_t nsyscall = -1;
#       if ME_OS == ME_OS_LINUX
        nsyscall = __NR_munmap;
#       elif ME_OS == ME_OS_BSD
        nsyscall = SYS_munmap;
#       endif

        ret = (
            !ME_SyscallEx(pid,
                          nsyscall,
                          (me_void_t *)addr,
                          (me_void_t *)(me_uintptr_t)size,
                          ME_NULLPTR,
                          ME_NULLPTR,
                          ME_NULLPTR,
                          ME_NULLPTR)
        ) ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_FreeMemory(me_address_t addr,
              me_size_t    size)
{
    me_bool_t ret = ME_FALSE;
#   if ME_OS == ME_OS_WIN
    {
        ret = VirtualFree(addr, 0, MEM_RELEASE) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        ret = !munmap(addr, size) ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_size_t
ME_DetourCodeEx(me_pid_t       pid,
                me_address_t   src,
                me_address_t   dst,
                me_detour_t    detour)
{
    me_size_t byte_count = 0;

    if (pid == (me_pid_t)ME_BAD)
        return byte_count;

#   if ME_ARCH == ME_ARCH_X86
    switch (detour)
    {
    case ME_DETOUR_JMP32:
        {
            me_byte_t code[] =
            {
                0xE9, 0x0, 0x0, 0x0, 0x0
            };

            *(me_uint32_t *)(&code[1]) = (me_uint32_t)(
                (me_uintptr_t)dst - (me_uintptr_t)src - sizeof(code)
            );

            byte_count = ME_WriteMemoryEx(pid, src, code, sizeof(code));
        }
        break;
    case ME_DETOUR_JMP64:
        {
            me_byte_t code[] =
            {
                0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#               if ME_ARCH_SIZE == 64
                , 0x0, 0x0, 0x0, 0x0
#               endif
            };

            *(me_uintptr_t *)(&code[6]) = (me_uintptr_t)dst;

            byte_count = ME_WriteMemoryEx(pid, src, code, sizeof(code));
        }
        break;
    case ME_DETOUR_CALL32:
        {
            me_byte_t code[] =
            {
                0xE8, 0x0, 0x0, 0x0, 0x0
            };

            *(me_uint32_t *)(&code[1]) = (me_uint32_t)(
                (me_uintptr_t)dst - (me_uintptr_t)src - sizeof(code)
            );

            byte_count = ME_WriteMemoryEx(pid, src, code, sizeof(code));
        }
        break;
    case ME_DETOUR_CALL64:
        {
            me_byte_t code[] =
            {
                0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#               if ME_ARCH_SIZE == 64
                , 0x0, 0x0, 0x0, 0x0
#               endif
            };

            *(me_uintptr_t *)(&code[6]) = (me_uintptr_t)dst;

            byte_count = ME_WriteMemoryEx(pid, src, code, sizeof(code));
        }
        break;
    }
#   endif

    return byte_count;
}

ME_API me_size_t
ME_DetourCode(me_address_t   src,
              me_address_t   dst,
              me_detour_t    detour)
{
    me_size_t byte_count = 0;

#   if ME_ARCH == ME_ARCH_X86
    switch (detour)
    {
    case ME_DETOUR_JMP32:
        {
            me_byte_t code[] =
            {
                0xE9, 0x0, 0x0, 0x0, 0x0
            };

            *(me_uint32_t *)(&code[1]) = (me_uint32_t)(
                (me_uintptr_t)dst - (me_uintptr_t)src - sizeof(code)
            );

            byte_count = ME_WriteMemory(src, code, sizeof(code));
        }
        break;
    case ME_DETOUR_JMP64:
        {
            me_byte_t code[] =
            {
                0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#               if ME_ARCH_SIZE == 64
                , 0x0, 0x0, 0x0, 0x0
#               endif
            };

            *(me_uintptr_t *)(&code[6]) = (me_uintptr_t)dst;

            byte_count = ME_WriteMemory(src, code, sizeof(code));
        }
        break;
    case ME_DETOUR_CALL32:
        {
            me_byte_t code[] =
            {
                0xE8, 0x0, 0x0, 0x0, 0x0
            };

            *(me_uint32_t *)(&code[1]) = (me_uint32_t)(
                (me_uintptr_t)dst - (me_uintptr_t)src - sizeof(code)
            );

            byte_count = ME_WriteMemory(src, code, sizeof(code));
        }
        break;
    case ME_DETOUR_CALL64:
        {
            me_byte_t code[] =
            {
                0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#               if ME_ARCH_SIZE == 64
                , 0x0, 0x0, 0x0, 0x0
#               endif
            };

            *(me_uintptr_t *)(&code[6]) = (me_uintptr_t)dst;

            byte_count = ME_WriteMemory(src, code, sizeof(code));
        }
        break;
    }
#   endif

    return byte_count;
}

ME_API me_size_t
ME_TrampolineCodeEx(me_pid_t     pid,
                    me_address_t src,
                    me_size_t    size,
                    me_address_t tramp,
                    me_size_t    max_size)
{
    me_size_t byte_count = 0;

    if (pid == (me_pid_t)ME_BAD || size == 0)
        return byte_count;

#   if ME_ARCH == ME_ARCH_X86
    {
        me_byte_t *old_code;

        me_byte_t code[] =
        {
            0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#           if ME_ARCH_SIZE == 64
            , 0x0, 0x0, 0x0, 0x0
#           endif
        };

        if (size + sizeof(code) > max_size)
            return byte_count;

        old_code = (me_byte_t *)ME_malloc(size);

        if (!old_code)
            return byte_count;

        if (ME_ReadMemoryEx(pid, src, old_code, size))
        {
            *(me_uintptr_t *)(&code[6]) = (me_uintptr_t)(&((me_byte_t *)src)[size]);

            byte_count += ME_WriteMemoryEx(pid, tramp, old_code, size);
            byte_count += ME_WriteMemoryEx(
                pid,
                (me_address_t)(&((me_byte_t *)tramp)[size]),
                code,
                sizeof(code)
            );

            if (byte_count != size + sizeof(code))
                byte_count = 0;
        }

        ME_free(old_code);  
    }
#   endif

    return byte_count;
}

ME_API me_size_t
ME_TrampolineCode(me_address_t src,
                  me_size_t    size,
                  me_byte_t   *tramp,
                  me_size_t    max_size)
{
    me_size_t byte_count = 0;

    if (size == 0)
        return byte_count;

#   if ME_ARCH == ME_ARCH_X86
    {
        me_byte_t *old_code;

        me_byte_t code[] =
        {
            0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
#           if ME_ARCH_SIZE == 64
            , 0x0, 0x0, 0x0, 0x0
#           endif
        };

        if (size + sizeof(code) > max_size)
            return byte_count;

        old_code = (me_byte_t *)ME_malloc(size);

        if (!old_code)
            return byte_count;

        if (ME_ReadMemory(src, old_code, size))
        {
            *(me_uintptr_t *)(&code[6]) = (me_uintptr_t)(&((me_byte_t *)src)[size]);

            byte_count += ME_WriteMemory(tramp, old_code, size);
            byte_count += ME_WriteMemory(
                (me_address_t)(&((me_byte_t *)tramp)[size]),
                code,
                sizeof(code)
            );

            if (byte_count != size + sizeof(code))
                byte_count = 0;
        }

        ME_free(old_code);  
    }
#   endif

    return byte_count;
}

ME_API me_void_t *
ME_SyscallEx(me_pid_t   pid,
             me_int_t   nsyscall,
             me_void_t *arg0,
             me_void_t *arg1,
             me_void_t *arg2,
             me_void_t *arg3,
             me_void_t *arg4,
             me_void_t *arg5)
{
    me_void_t *ret = (me_void_t *)ME_BAD;
    me_regs_t regs, old_regs;
    me_bool_t debugged;
    me_address_t inj_addr;
#   if ME_ARCH == ME_ARCH_X86
#   if ME_ARCH_SIZE == 64
    me_byte_t code[] = 
    {
        0x0F, 0x05
    };
#   else
    me_byte_t code[] = 
    {
        0xCD, 0x80
    };
#   endif
#   endif
    me_byte_t old_code[sizeof(code)];

    debugged = ME_GetStateDbg(pid);

    if (!debugged)
    {
        me_bool_t check;
        check = ME_AttachDbg(pid);
        check &= ME_WaitDbg();
        if (!check)
            return ret;
    }

    ME_GetRegsDbg(pid, &old_regs);
    regs = old_regs;
#   if ME_ARCH == ME_ARCH_X86
#   if ME_ARCH_SIZE == 64
    inj_addr = (me_address_t)ME_ReadRegDbg(ME_REGID_RIP, regs);
#   else
    inj_addr = (me_address_t)ME_ReadRegDbg(ME_REGID_EIP, regs);
#   endif
#   endif

    if (!ME_ReadMemoryDbg(pid, inj_addr, old_code, sizeof(old_code)) ||
        !ME_WriteMemoryDbg(pid, inj_addr, code, sizeof(code)))
    {
        goto L_DETACH;
    }
    
#   if ME_ARCH == ME_ARCH_X86
#   if ME_ARCH_SIZE == 64
    ME_WriteRegDbg((me_uintptr_t)nsyscall, ME_REGID_RAX, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg0, ME_REGID_RDI, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg1, ME_REGID_RSI, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg2, ME_REGID_RDX, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg3, ME_REGID_R10, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg4, ME_REGID_R8, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg5, ME_REGID_R9, &regs);
#   else
    ME_WriteRegDbg((me_uintptr_t)nsyscall, ME_REGID_EAX, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg0, ME_REGID_EBX, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg1, ME_REGID_ECX, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg2, ME_REGID_EDX, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg3, ME_REGID_ESI, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg4, ME_REGID_EDI, &regs);
    ME_WriteRegDbg((me_uintptr_t)arg5, ME_REGID_EBP, &regs);
#   endif
#   endif

    ME_SetRegsDbg(pid, regs);
    ME_StepDbg(pid);
    ME_WaitProcessDbg(pid);
    ME_GetRegsDbg(pid, &regs);
#   if ME_ARCH == ME_ARCH_X86
#   if ME_ARCH_SIZE == 64
    ret = (me_void_t *)ME_ReadRegDbg(ME_REGID_RAX, regs);
#   else
    ret = (me_void_t *)ME_ReadRegDbg(ME_REGID_EAX, regs);
#   endif
#   endif

    ME_WriteMemoryDbg(pid, inj_addr, old_code, sizeof(old_code));
    ME_SetRegsDbg(pid, old_regs);
L_DETACH:
    if (!debugged)
        ME_DetachDbg(pid);

    return ret;
}

ME_API me_void_t *
ME_Syscall(me_int_t   nsyscall,
           me_void_t *arg0,
           me_void_t *arg1,
           me_void_t *arg2,
           me_void_t *arg3,
           me_void_t *arg4,
           me_void_t *arg5)
{
    me_void_t *ret = (me_void_t *)ME_FALSE;
#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        ret = (me_void_t *)syscall(nsyscall, arg0, arg1, arg2, arg3, arg4, arg5);
    }
#   endif

    return ret;
}

/****************************************/

ME_API me_bool_t
ME_AttachDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = DebugActiveProcess(pid) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        ret = (
            ptrace(PTRACE_ATTACH, pid, NULL, NULL)
         ) != -1 ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_DetachDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = DebugActiveProcessStop(pid) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        ret = (
            ptrace(PTRACE_DETACH, pid, NULL, NULL)
         ) != -1 ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_int_t
ME_GetStateDbg(me_pid_t pid)
{
    me_int_t ret = (me_int_t)ME_BAD;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        BOOL Check = FALSE;
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProcess)
            return ret;

        CheckRemoteDebuggerPresent(hProcess, &Check);

        ret = Check == TRUE ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        me_tchar_t *status_file = (me_tchar_t *)ME_NULL;
        {
            int fd;
            me_tchar_t status_path[64] = { 0 };
            me_tchar_t read_buf[1024] = { 0 };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            me_tchar_t *old_status_file;

            ME_SNPRINTF(status_path, ME_ARRLEN(status_path) - 1,
                        ME_STR("/proc/%d/status"), pid);
            fd = open(status_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                old_status_file = status_file;
                status_file = (me_tchar_t *)ME_calloc(
                    read_len * (++read_count),
                    sizeof(status_file[0])
                );

                if (old_status_file != (me_tchar_t *)ME_NULL)
                {
                    if (status_file)
                    {
                        ME_MEMCPY(
                            status_file, old_status_file,
                            (read_count - 1) *
                                read_len *
                                sizeof(status_file[0])
                        );
                    }

                    ME_free(old_status_file);
                }

                if (!status_file)
                    return ret;

                ME_MEMCPY(&status_file[(read_count - 1) * read_len], 
                          read_buf, sizeof(read_buf));
            }

            old_status_file = status_file;
            status_file = ME_calloc(
                    (read_len * read_count) + 1,
                    sizeof(status_file[0])
            );

            if (status_file)
            {
                ME_MEMCPY(status_file, old_status_file,
                          read_len * read_count);
                status_file[(read_len * read_count)] = ME_STR('\00');
            }

            ME_free(old_status_file);

            if (!status_file)
                return ret;
        }

        {
            me_tchar_t *tracer_str;
            me_tchar_t match[] = ME_STR("TracerPid:\t");
            if ((tracer_str = ME_STRSTR(status_file,  ME_STR(match))))
            {
                ret = ME_STRTOL(&tracer_str[ME_ARRLEN(match) - 1],
                                NULL,
                                10) ? ME_TRUE : ME_FALSE;
            }

            else
            {
                ret = ME_FALSE;
            }
        }

        ME_free(status_file);
    }
#   endif

    return ret;
}

ME_API me_size_t
ME_ReadMemoryDbg(me_pid_t     pid,
                 me_address_t src,
                 me_byte_t   *dst,
                 me_size_t    size)
{
    me_size_t byte_count = 0;

    if (pid == (me_pid_t)ME_BAD || !dst || size == 0)
        return byte_count;

#   if ME_OS == ME_OS_WIN
    {
        byte_count = ME_ReadMemoryEx(pid, src, dst, size);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_size_t i;
        for (i = 0; i < size; ++i)
        {
            long data = ptrace(PTRACE_PEEKDATA,
                               pid,
                               (&((me_byte_t *)src)[i]),
                               NULL);
            
            if (data == -1)
                return byte_count;

            dst[i] = (me_byte_t)data;
        }

        byte_count = i;
    }
#   elif ME_OS == ME_OS_BSD
    {

    }
#   endif

    return byte_count;
}

ME_API me_size_t
ME_WriteMemoryDbg(me_pid_t     pid,
                  me_address_t dst,
                  me_byte_t   *src,
                  me_size_t    size)
{
    me_size_t byte_count = 0;

    if (pid == (me_pid_t)ME_BAD || !src || size == 0)
        return byte_count;

#   if ME_OS == ME_OS_WIN
    {
        byte_count = ME_WriteMemory(pid, dst, src, size);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        me_size_t i;
        me_size_t buf_size = size + sizeof(long) - (size % sizeof(long));
        me_byte_t *buf = (me_byte_t *)ME_malloc(buf_size);

        if (!buf)
            return byte_count;

        if (!ME_ReadMemoryDbg(pid, dst, buf, buf_size))
            goto L_CLEAN;

        for (i = 0; i < size; ++i)
            buf[i] = src[i];

        for (i = 0; i < buf_size; i += sizeof(long))
        {
            long data = *(long *)&buf[i];
            if (ptrace(PTRACE_POKEDATA, pid,
                       (&((me_byte_t *)dst)[i]), data) == -1)
            {
                goto L_CLEAN;
            }
        }

        byte_count = i;
    L_CLEAN:
        ME_free(buf);
    }
#   endif

    return byte_count;
}

ME_API me_bool_t
ME_GetRegsDbg(me_pid_t   pid,
              me_regs_t *pregs)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD || !pregs)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        DWORD threadID = 0;
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 entry;
            entry.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hSnap, &entry))
            {
                do
                {
                    me_pid_t cur_pid = (me_pid_t)entry.th32OwnerProcessID;
                    if (cur_pid == pid)
                    {
                        threadID = entry.th32ThreadID;
                        break;
                    }
                } while(Thread32Next(hSnap, &entry));
            }

            CloseHandle(hSnap);
        }

        if (threadID)
        {
            CONTEXT ctx;
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);

            if (!hThread)
                return ret;

            if (GetThreadContext(hThread, &ctx))
            {
                *pregs = ctx;
                ret = ME_TRUE;
            }
        }
    }
#   elif ME_OS == ME_OS_LINUX
    {
        ret = (ptrace(PTRACE_GETREGS, pid,
                      NULL, pregs) != -1) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_BSD
    {
        ret = (ptrace(PT_GETREGS, pid,
                      (caddr_t)pregs, 0) != -1) ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_SetRegsDbg(me_pid_t  pid,
              me_regs_t regs)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        DWORD threadID = 0;
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 entry;
            entry.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hSnap, &entry))
            {
                do
                {
                    me_pid_t cur_pid = (me_pid_t)entry.th32OwnerProcessID;
                    if (cur_pid == pid)
                    {
                        threadID = entry.th32ThreadID;
                        break;
                    }
                } while(Thread32Next(hSnap, &entry));
            }

            CloseHandle(hSnap);
        }

        if (threadID)
        {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);

            if (!hThread)
                return ret;

            if (SetThreadContext(hThread, &regs))
                ret = ME_TRUE;
        }
    }
#   elif ME_OS == ME_OS_LINUX
    {
        ret = (ptrace(PTRACE_SETREGS, pid,
                      NULL, &regs) != -1) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_BSD
    {
        ret = (ptrace(PT_SETREGS, pid,
                      (caddr_t)pregs, 0) != -1) ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_uintptr_t
ME_ReadRegDbg(me_regid_t   reg,
              me_regs_t    regs)
{
    me_uintptr_t val = (me_uintptr_t)ME_BAD;
#   if ME_OS == ME_OS_WIN
    {
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        switch (reg)
        {
        case ME_REGID_RAX:
            val = regs.Rax;
            break;
        case ME_REGID_RBX:
            val = regs.Rbx;
            break;
        case ME_REGID_RCX:
            val = regs.Rcx;
            break;
        case ME_REGID_RDX:
            val = regs.Rdx;
            break;
        case ME_REGID_RSI:
            val = regs.Rsi;
            break;
        case ME_REGID_RDI:
            val = regs.Rdi;
            break;
        case ME_REGID_RBP:
            val = regs.Rbp;
            break;
        case ME_REGID_RSP:
            val = regs.Rsp;
            break;
        case ME_REGID_RIP:
            val = regs.Rip;
            break;
        case ME_REGID_R8:
            val = regs.R8;
            break;
        case ME_REGID_R9:
            val = regs.R9;
            break;
        case ME_REGID_R10:
            val = regs.R10;
            break;
        case ME_REGID_R11:
            val = regs.R11;
            break;
        case ME_REGID_R12:
            val = regs.R12;
            break;
        case ME_REGID_R13:
            val = regs.R13;
            break;
        case ME_REGID_R14:
            val = regs.R14;
            break;
        case ME_REGID_R15:
            val = regs.R15;
            break;
        default:
            return ret;
        }

#       else
        switch (reg)
        {
        case ME_REGID_EAX:
            val = regs.Eax;
            break;
        case ME_REGID_EBX:
            val = regs.Ebx;
            break;
        case ME_REGID_ECX:
            val = regs.Ecx;
            break;
        case ME_REGID_EDX:
            val = regs.Edx;
            break;
        case ME_REGID_ESI:
            val = regs.Esi;
            break;
        case ME_REGID_EDI:
            val = regs.Edi;
            break;
        case ME_REGID_EBP:
            val = regs.Ebp;
            break;
        case ME_REGID_ESP:
            val = regs.Esp;
            break;
        case ME_REGID_EIP:
            val = regs.Eip;
            break;
        default:
            return ret;
        }
#       endif
#       endif
    }
#   elif ME_OS == ME_OS_LINUX
    {
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        switch (reg)
        {
        case ME_REGID_RAX:
            val = regs.rax;
            break;
        case ME_REGID_RBX:
            val = regs.rbx;
            break;
        case ME_REGID_RCX:
            val = regs.rcx;
            break;
        case ME_REGID_RDX:
            val = regs.rdx;
            break;
        case ME_REGID_RSI:
            val = regs.rsi;
            break;
        case ME_REGID_RDI:
            val = regs.rdi;
            break;
        case ME_REGID_RBP:
            val = regs.rbp;
            break;
        case ME_REGID_RSP:
            val = regs.rsp;
            break;
        case ME_REGID_RIP:
            val = regs.rip;
            break;
        case ME_REGID_R8:
            val = regs.r8;
            break;
        case ME_REGID_R9:
            val = regs.r9;
            break;
        case ME_REGID_R10:
            val = regs.r10;
            break;
        case ME_REGID_R11:
            val = regs.r11;
            break;
        case ME_REGID_R12:
            val = regs.r12;
            break;
        case ME_REGID_R13:
            val = regs.r13;
            break;
        case ME_REGID_R14:
            val = regs.r14;
            break;
        case ME_REGID_R15:
            val = regs.r15;
            break;
        }
#       else
        switch (reg)
        {
        case ME_REGID_EAX:
            val = regs.eax;
            break;
        case ME_REGID_EBX:
            val = regs.ebx;
            break;
        case ME_REGID_ECX:
            val = regs.ecx;
            break;
        case ME_REGID_EDX:
            val = regs.edx;
            break;
        case ME_REGID_ESI:
            val = regs.esi;
            break;
        case ME_REGID_EDI:
            val = regs.edi;
            break;
        case ME_REGID_EBP:
            val = regs.ebp;
            break;
        case ME_REGID_ESP:
            val = regs.esp;
            break;
        case ME_REGID_EIP:
            val = regs.eip;
            break;
        }
#       endif
#       endif
    }
#   elif ME_OS == ME_OS_BSD
    {
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        switch (reg)
        {
        case ME_REGID_RAX:
            pregs->r_rax = val;
            break;
        case ME_REGID_RBX:
            pregs->r_rbx = val;
            break;
        case ME_REGID_RCX:
            pregs->r_rcx = val;
            break;
        case ME_REGID_RDX:
            pregs->r_rdx = val;
            break;
        case ME_REGID_RSI:
            pregs->r_rsi = val;
            break;
        case ME_REGID_RDI:
            pregs->r_rdi = val;
            break;
        case ME_REGID_RBP:
            pregs->r_rbp = val;
            break;
        case ME_REGID_RSP:
            pregs->r_rsp = val;
            break;
        case ME_REGID_RIP:
            pregs->r_rip = val;
            break;
        case ME_REGID_R8:
            pregs->r_r8 = val;
            break;
        case ME_REGID_R9:
            pregs->r_r9 = val;
            break;
        case ME_REGID_R10:
            pregs->r_r10 = val;
            break;
        case ME_REGID_R11:
            pregs->r_r11 = val;
            break;
        case ME_REGID_R12:
            pregs->r_r12 = val;
            break;
        case ME_REGID_R13:
            pregs->r_r13 = val;
            break;
        case ME_REGID_R14:
            pregs->r_r14 = val;
            break;
        case ME_REGID_R15:
            pregs->r_r15 = val;
            break;
        }
#       else
        switch (reg)
        {
        case ME_REGID_EAX:
            pregs->r_eax = val;
            break;
        case ME_REGID_EBX:
            pregs->r_ebx = val;
            break;
        case ME_REGID_ECX:
            pregs->r_ecx = val;
            break;
        case ME_REGID_EDX:
            pregs->r_edx = val;
            break;
        case ME_REGID_ESI:
            pregs->r_esi = val;
            break;
        case ME_REGID_EDI:
            pregs->r_edi = val;
            break;
        case ME_REGID_EBP:
            pregs->r_ebp = val;
            break;
        case ME_REGID_ESP:
            pregs->r_esp = val;
            break;
        case ME_REGID_EIP:
            pregs->r_eip = val;
            break;
        }
#       endif
#       endif
    }
#   endif

    return val;
}

ME_API me_bool_t
ME_WriteRegDbg(me_uintptr_t val,
               me_regid_t   reg,
               me_regs_t   *pregs)
{
    me_bool_t ret = ME_FALSE;

    if (!pregs)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        switch (reg)
        {
        case ME_REGID_RAX:
            pregs->Rax = val;
            break;
        case ME_REGID_RBX:
            pregs->Rbx = val;
            break;
        case ME_REGID_RCX:
            pregs->Rcx = val;
            break;
        case ME_REGID_RDX:
            pregs->Rdx = val;
            break;
        case ME_REGID_RSI:
            pregs->Rsi = val;
            break;
        case ME_REGID_RDI:
            pregs->Rdi = val;
            break;
        case ME_REGID_RBP:
            pregs->Rbp = val;
            break;
        case ME_REGID_RSP:
            pregs->Rsp = val;
            break;
        case ME_REGID_RIP:
            pregs->Rip = val;
            break;
        case ME_REGID_R8:
            pregs->R8 = val;
            break;
        case ME_REGID_R9:
            pregs->R9 = val;
            break;
        case ME_REGID_R10:
            pregs->R10 = val;
            break;
        case ME_REGID_R11:
            pregs->R11 = val;
            break;
        case ME_REGID_R12:
            pregs->R12 = val;
            break;
        case ME_REGID_R13:
            pregs->R13 = val;
            break;
        case ME_REGID_R14:
            pregs->R14 = val;
            break;
        case ME_REGID_R15:
            pregs->R15 = val;
            break;
        default:
            return ret;
        }

#       else
        switch (reg)
        {
        case ME_REGID_EAX:
            pregs->Eax = val;
            break;
        case ME_REGID_EBX:
            pregs->Ebx = val;
            break;
        case ME_REGID_ECX:
            pregs->Ecx = val;
            break;
        case ME_REGID_EDX:
            pregs->Edx = val;
            break;
        case ME_REGID_ESI:
            pregs->Esi = val;
            break;
        case ME_REGID_EDI:
            pregs->Edi = val;
            break;
        case ME_REGID_EBP:
            pregs->Ebp = val;
            break;
        case ME_REGID_ESP:
            pregs->Esp = val;
            break;
        case ME_REGID_EIP:
            pregs->Eip = val;
            break;
        default:
            return ret;
        }
#       endif

        ret = ME_TRUE;

#       endif
    }
#   elif ME_OS == ME_OS_LINUX
    {
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        switch (reg)
        {
        case ME_REGID_RAX:
            pregs->rax = val;
            break;
        case ME_REGID_RBX:
            pregs->rbx = val;
            break;
        case ME_REGID_RCX:
            pregs->rcx = val;
            break;
        case ME_REGID_RDX:
            pregs->rdx = val;
            break;
        case ME_REGID_RSI:
            pregs->rsi = val;
            break;
        case ME_REGID_RDI:
            pregs->rdi = val;
            break;
        case ME_REGID_RBP:
            pregs->rbp = val;
            break;
        case ME_REGID_RSP:
            pregs->rsp = val;
            break;
        case ME_REGID_RIP:
            pregs->rip = val;
            break;
        case ME_REGID_R8:
            pregs->r8 = val;
            break;
        case ME_REGID_R9:
            pregs->r9 = val;
            break;
        case ME_REGID_R10:
            pregs->r10 = val;
            break;
        case ME_REGID_R11:
            pregs->r11 = val;
            break;
        case ME_REGID_R12:
            pregs->r12 = val;
            break;
        case ME_REGID_R13:
            pregs->r13 = val;
            break;
        case ME_REGID_R14:
            pregs->r14 = val;
            break;
        case ME_REGID_R15:
            pregs->r15 = val;
            break;
        }
#       else
        switch (reg)
        {
        case ME_REGID_EAX:
            pregs->eax = val;
            break;
        case ME_REGID_EBX:
            pregs->ebx = val;
            break;
        case ME_REGID_ECX:
            pregs->ecx = val;
            break;
        case ME_REGID_EDX:
            pregs->edx = val;
            break;
        case ME_REGID_ESI:
            pregs->esi = val;
            break;
        case ME_REGID_EDI:
            pregs->edi = val;
            break;
        case ME_REGID_EBP:
            pregs->ebp = val;
            break;
        case ME_REGID_ESP:
            pregs->esp = val;
            break;
        case ME_REGID_EIP:
            pregs->eip = val;
            break;
        }
#       endif

        ret = ME_TRUE;

#       endif
    }
#   elif ME_OS == ME_OS_BSD
    {
#       if ME_ARCH == ME_ARCH_X86
#       if ME_ARCH_SIZE == 64
        switch (reg)
        {
        case ME_REGID_RAX:
            pregs->r_rax = val;
            break;
        case ME_REGID_RBX:
            pregs->r_rbx = val;
            break;
        case ME_REGID_RCX:
            pregs->r_rcx = val;
            break;
        case ME_REGID_RDX:
            pregs->r_rdx = val;
            break;
        case ME_REGID_RSI:
            pregs->r_rsi = val;
            break;
        case ME_REGID_RDI:
            pregs->r_rdi = val;
            break;
        case ME_REGID_RBP:
            pregs->r_rbp = val;
            break;
        case ME_REGID_RSP:
            pregs->r_rsp = val;
            break;
        case ME_REGID_RIP:
            pregs->r_rip = val;
            break;
        case ME_REGID_R8:
            pregs->r_r8 = val;
            break;
        case ME_REGID_R9:
            pregs->r_r9 = val;
            break;
        case ME_REGID_R10:
            pregs->r_r10 = val;
            break;
        case ME_REGID_R11:
            pregs->r_r11 = val;
            break;
        case ME_REGID_R12:
            pregs->r_r12 = val;
            break;
        case ME_REGID_R13:
            pregs->r_r13 = val;
            break;
        case ME_REGID_R14:
            pregs->r_r14 = val;
            break;
        case ME_REGID_R15:
            pregs->r_r15 = val;
            break;
        }
#       else
        switch (reg)
        {
        case ME_REGID_EAX:
            pregs->r_eax = val;
            break;
        case ME_REGID_EBX:
            pregs->r_ebx = val;
            break;
        case ME_REGID_ECX:
            pregs->r_ecx = val;
            break;
        case ME_REGID_EDX:
            pregs->r_edx = val;
            break;
        case ME_REGID_ESI:
            pregs->r_esi = val;
            break;
        case ME_REGID_EDI:
            pregs->r_edi = val;
            break;
        case ME_REGID_EBP:
            pregs->r_ebp = val;
            break;
        case ME_REGID_ESP:
            pregs->r_esp = val;
            break;
        case ME_REGID_EIP:
            pregs->r_eip = val;
            break;
        }
#       endif

        ret = ME_TRUE;

#       endif
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_WaitDbg(me_void_t)
{
#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int status;
        wait(&status);
    }
#   endif

    return ME_TRUE;
}

ME_API me_bool_t
ME_WaitProcessDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int status;
        ret = waitpid(pid,
                      &status,
                      WSTOPPED) != (pid_t)-1 ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_ContinueDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX
    {
        ret = ptrace(PTRACE_CONT, pid,
                     NULL, NULL) != -1 ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_BSD
    {
        ret = ptrace(PT_CONTINUE, pid,
                     NULL, NULL) != -1 ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_StepDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX
    {
        ret = ptrace(PTRACE_SINGLESTEP, pid,
                     NULL, NULL) != -1 ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_BSD
    {
        ret = ptrace(PT_STEP, pid,
                     NULL, NULL) != -1 ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_BreakDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
            return ret;
        ret = DebugBreakProcess(hProcess) ? ME_TRUE : ME_FALSE;
        CloseHandle(hProcess);
    }
#   elif ME_OS == ME_OS_LINUX
    {
        if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) != -1)
            ret = ME_TRUE;
    }
#   elif ME_OS == ME_OS_BSD
    {
        if (ptrace(PT_SUSPEND, pid, NULL, NULL) != -1)
            ret = ME_TRUE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_KillDbg(me_pid_t pid)
{
    me_bool_t ret = ME_FALSE;

    if (pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX
    {
        if (ptrace(PTRACE_KILL, pid, NULL, NULL) != -1)
            ret = ME_TRUE;
    }
#   elif ME_OS == ME_OS_BSD
    {
        if (ptrace(PT_KILL, pid, NULL, NULL) != -1)
            ret = ME_TRUE;
    }
#   endif

    return ret;
}

#endif

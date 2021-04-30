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

/****************************************/

ME_API void *
ME_malloc(size_t size)
{
    return ME_MALLOC(size);
}

ME_API void *
ME_calloc(size_t nmemb, size_t size)
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
ME_EnumProcesses(me_bool_t(*callback)(me_pid_t pid, me_void_t *arg),
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
ME_GetProcessPathEx(me_pid_t     pid,
                    me_tchar_t  *proc_path,
                    me_size_t    max_len)
{
    me_size_t chr_count = 0;

    if (!proc_path || max_len == 0)
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
ME_GetProcessPath(me_tchar_t  *proc_path,
                  me_size_t    max_len)
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
ME_GetProcessNameEx(me_pid_t     pid,
                    me_tchar_t  *proc_name,
                    me_size_t    max_len)
{
    me_size_t chr_count = 0;

    if (!proc_name || max_len == 0)
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
ME_GetProcessName(me_tchar_t  *proc_name,
                  me_size_t    max_len)
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
            ME_SNPRINTF(status_path, ME_ARRLEN(status_path) - 1,
                        ME_STR("/proc/%d/status"), pid);
            fd = open(status_path, O_RDONLY);
            if (fd == -1)
                return ppid;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                me_tchar_t *old_status_file = status_file;
                status_file = (me_tchar_t *)ME_calloc(
                    (read_len * ++read_count) + 1,
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

                ME_MEMCPY(&status_file[(read_count - 1) * read_len], read_buf, sizeof(read_buf));

                status_file[read_len] = ME_STR('\00');
            }
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

    if (!callback || pid == (me_pid_t)ME_BAD)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_EnumModules2Ex(pid, callback, arg, (me_void_t *)ME_NULL);
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
            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return ret;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                me_tchar_t *old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    (read_len * ++read_count) + 1,
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

                ME_MEMCPY(&maps_file[(read_count - 1) * read_len], read_buf, sizeof(read_buf));

                maps_file[read_len - 1] = ME_STR('\00');
            }
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

    if (!callback || pid == (me_pid_t)ME_BAD)
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

    if (arg.mod_ref && arg.pmod)
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

    if (arg.mod_ref && arg.pmod)
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

ME_API me_size_t
ME_GetModulePathEx(me_pid_t    pid,
                   me_module_t mod,
                   me_tchar_t *mod_path,
                   me_size_t   max_len)
{
    me_size_t chr_count = 0;
#   if ME_OS == ME_OS_WIN
    {
        chr_count = ME_GetModulePath2Ex(pid, mod, mod_path,
                                        max_len, (me_void_t *)ME_NULL);
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
            ME_SNPRINTF(maps_path, ME_ARRLEN(maps_path) - 1,
                        ME_STR("/proc/%d/maps"), pid);
            fd = open(maps_path, O_RDONLY);
            if (fd == -1)
                return chr_count;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                me_tchar_t *old_maps_file = maps_file;
                maps_file = (me_tchar_t *)ME_calloc(
                    (read_len * ++read_count) + 1,
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
                          read_buf,
                          sizeof(read_buf));

                maps_file[read_len - 1] = ME_STR('\00');
            }
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
                ME_MEMCPY(mod_path, mod_path_str, chr_count * sizeof(me_tchar_t));
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
#   if ME_OS == ME_OS_WIN
    {
        chr_count = ME_GetModulePath2(mod, mod_path, 
                                      max_len, (me_void_t *)ME_NULL);
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
#   if ME_OS == ME_OS_WIN
    {
        HMODULE hModule = (HMODULE)NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPTSTR)mod.base, &hModule);
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

                ret = ME_TRUE;
            }
        }
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    me_tchar_t mod_path[ME_PATH_MAX] = { 0 };
    if (ME_GetModulePathEx(pid, mod, mod_path, ME_ARRLEN(mod_path)))
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

ME_API me_bool_t
ME_LoadModuleEx(me_pid_t     pid,
                me_tstring_t path)
{
    me_bool_t ret = ME_FALSE;
#   if ME_OS == ME_OS_WIN
    {
        ret = ME_LoadModule2Ex(pid, path, (me_void_t *)ME_NULL);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int mode = RTLD_LAZY;
        ret = ME_LoadModule2Ex(pid, path, (me_void_t *)&mode);
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_LoadModule2Ex(me_pid_t     pid,
                 me_tstring_t path,
                 me_void_t   *reserved)
{
    me_bool_t ret = ME_FALSE;

    if (!path)
        return ret;

#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_LoadModule(me_tstring_t path)
{
    me_bool_t ret = ME_FALSE;

    if (!path)
        return ret;

#   if ME_OS == ME_OS_WIN
    {
        ret = ME_LoadModule2(path, (me_void_t *)ME_NULL);
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {
        int mode = RTLD_LAZY;
        ret = ME_LoadModule2(path, (me_void_t *)&mode);
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
        ret = !dlopen(path, *pmode) ? ME_TRUE : ME_FALSE;
    }
#   endif

    return ret;
}

ME_API me_bool_t
ME_UnloadModuleEx(me_pid_t    pid,
                  me_module_t mod)
{
    me_bool_t ret = ME_FALSE;
#   if ME_OS == ME_OS_WIN
    {

    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_LINUX
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
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPTSTR)mod.base, &hModule);
        if (!hModule)
            return chr_count;
        ret = FreeLibrary(hModule) ? ME_TRUE : ME_FALSE;
    }
#   elif ME_OS == ME_OS_LINUX || ME_OS == ME_OS_BSD
    {

    }
#   endif

    return ret;
}

#endif

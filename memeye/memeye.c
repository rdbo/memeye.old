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
#   if   ME_OS == ME_OS_WIN
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &entry))
            {
                while(
                    callback((me_pid_t)entry.th32ProcessID, arg) != ME_FALSE &&
                    Process32Next(hSnap, &entry)
                );
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
            if (pid || (!pid && ME_STRCMP(pdirent->d_name, ME_STR("0"))))
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
    me_tchar_t proc_path[ME_PATH_MAX] = {  };
    if (ME_GetProcessPathEx(pid, proc_path, 
                            ME_ARRLEN(proc_path) - 1) == ME_TRUE)
    {
        me_size_t proc_ref_len = ME_STRLEN(parg->proc_ref);
        if (proc_ref_len <= ME_PATH_MAX)
        {
            if (!ME_STRCMP(&proc_path[ME_PATH_MAX - proc_ref_len], 
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
    me_tchar_t exe_path[64] = {  };
    ME_SNPRINTF(exe_path, ME_ARRLEN(exe_path) - 1,
                ME_STR("/proc/%d/exe"), pid);
    chr_count = (me_size_t)readlink(exe_path, proc_path, max_len);
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

#   if ME_OS == ME_OS_WIN || ME_OS == ME_OS_LINUX
    {
        me_tchar_t proc_path[ME_PATH_MAX] = {  };
        if (ME_GetProcessPathEx(pid, proc_path, ME_ARRLEN(proc_path) - 1))
        {
            me_tchar_t path_chr;
            me_tchar_t *tmp;

#           if ME_OS == ME_OS_WIN
            path_chr = ME_STR('\\');
#           elif ME_OS == ME_OS_LINUX
            path_chr = ME_STR('/');
#           endif

            for (tmp = proc_path; (tmp = ME_STRCHR(proc_path, path_chr)); tmp = &tmp[1]);

            chr_count = ME_STRLEN(tmp);
            if (chr_count > max_len)
                chr_count = max_len;

            ME_MEMCPY((void *)proc_name, (void *)tmp, 
                      chr_count * sizeof(proc_name[0]));
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
#   if ME_OS == ME_OS_WIN
    {
        me_tchar_t proc_path[ME_PATH_MAX];
        if (ME_GetProcessPath(proc_path, ME_ARRLEN(proc_path) - 1))
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
        int fd;
        me_tchar_t *status_file = (me_tchar_t *)ME_NULL;
        {
            me_tchar_t status_path[64] = {  };
            me_tchar_t read_buf[1024] = {  };
            me_size_t  read_len = ME_ARRLEN(read_buf);
            me_size_t  read_count = 0;
            ME_SNPRINTF(status_path, ME_ARRLEN(status_path) - 1,
                        ME_STR("/proc/%d/status"), pid);
            fd = open(status_path, O_RDONLY);
            if (fd == -1 || !(status_file = ME_malloc(read_len)))
                return ppid;

            while((read(fd, read_buf, sizeof(read_buf))) > 0)
            {
                me_tchar_t *old_status_file = status_file;
                status_file = ME_calloc((read_len * ++read_count) + 1,
                                        sizeof(status_file[0]));

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

#endif

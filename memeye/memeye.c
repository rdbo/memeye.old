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
    return malloc(size);
}

ME_API void *
ME_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

ME_API void
ME_free(void *ptr)
{
    free(ptr);
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
    if (ME_GetProcessPathEx(pid, proc_path, ME_PATH_MAX - 1) == ME_TRUE)
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

    if (!proc_path)
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

#endif

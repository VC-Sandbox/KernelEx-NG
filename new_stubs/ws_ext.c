/*
 * ws_ext.c - KernelEx-NG: getaddrinfo / freeaddrinfo / getnameinfo for Windows 98 (IPv4), with tracing.
 *
 * Windows 98's Winsock 2 has no getaddrinfo. KernelEx 4.5 gives programs Microsoft's wspiapi.h fallback
 * (kexbasen addinfo.c). kexnt now provides its own, built on WS2_32's gethostbyname / getservbyname, so a
 * name lookup leaves a line in KEXTRACE_<program>.LOG ("getaddrinfo <name>" and the result) - Mypal 29 said
 * "Server not found" with a working network (2026-11-02) and nothing showed where the lookup went.
 * Error codes are the Windows ones (EAI_* = WSA* values).
 */
#include "kexnt_common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <x86intrin.h>   /* __rdtsc with GCC */
#include <string.h>
#include <intrin.h>

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef struct hostent *(WSAAPI *T_GHBN)(const char *);
typedef struct servent *(WSAAPI *T_GSBN)(const char *, const char *);
typedef struct hostent *(WSAAPI *T_GHBA)(const char *, int, int);
typedef struct servent *(WSAAPI *T_GSBP)(int, const char *);
typedef unsigned long (WSAAPI *T_INADDR)(const char *);
typedef int (WSAAPI *T_WSAGLE)(void);
typedef char *(WSAAPI *T_NTOA)(struct in_addr);

/* kexnt imports only KERNEL32/ADVAPI32: no ws2_32 byte-order helpers */
#define BS16(x) ((USHORT)((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF)))
#define BS32(x) ((((x) & 0xFFUL) << 24) | (((x) & 0xFF00UL) << 8) | (((x) >> 8) & 0xFF00UL) | (((x) >> 24) & 0xFFUL))
static FARPROC ws(const char *n) { return kex_sysproc("WS2_32.DLL", n); }
static struct hostent *dns_fallback(const char *name);

static void trace_name(const char *tag, const char *name, DWORD a, DWORD b, DWORD c)
{
    char line[160]; int n = 0;
    while (*tag && n < 40) line[n++] = *tag++;
    line[n++] = ' ';
    if (name) while (*name && n < (int)sizeof(line) - 1) line[n++] = *name++;
    line[n] = 0;
    kex_trace(line, a, b, c, 0);
}

static struct addrinfo *new_ai(ULONG addr, USHORT port, int socktype, int proto)
{
    struct addrinfo *ai = (struct addrinfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ai) + sizeof(struct sockaddr_in));
    struct sockaddr_in *sin;
    if (!ai) return NULL;
    sin = (struct sockaddr_in *)(ai + 1);
    sin->sin_family = AF_INET; sin->sin_port = port; sin->sin_addr.s_addr = addr;
    ai->ai_family = AF_INET; ai->ai_socktype = socktype; ai->ai_protocol = proto;
    ai->ai_addrlen = sizeof(*sin); ai->ai_addr = (struct sockaddr *)sin;
    return ai;
}

VOID KEXAPI kex_freeaddrinfo(struct addrinfo *ai)
{
    while (ai) {
        struct addrinfo *n = ai->ai_next;
        if (ai->ai_canonname) HeapFree(GetProcessHeap(), 0, ai->ai_canonname);
        HeapFree(GetProcessHeap(), 0, ai);
        ai = n;
    }
}

INT KEXAPI kex_getaddrinfo(PCSTR node, PCSTR service, const struct addrinfo *hints, struct addrinfo **res)
{
    T_GHBN ghbn = (T_GHBN)ws("gethostbyname"); T_GSBN gsbn = (T_GSBN)ws("getservbyname"); T_INADDR inaddr = (T_INADDR)ws("inet_addr");
    T_WSAGLE gle = (T_WSAGLE)ws("WSAGetLastError");
    int flags = 0, family = AF_UNSPEC, socktype = 0, proto = 0, i, rc = 0;
    USHORT port = 0; ULONG addrs[35]; int naddr = 0; const char *canon = NULL;
    struct addrinfo *head = NULL, **tail = &head;
    if (res) *res = NULL;
    if (!res || (!node && !service)) return WSAHOST_NOT_FOUND;
    if (hints) {
        if (hints->ai_addrlen || hints->ai_canonname || hints->ai_addr || hints->ai_next) return WSANO_RECOVERY;
        flags = hints->ai_flags; family = hints->ai_family; socktype = hints->ai_socktype; proto = hints->ai_protocol;
    }
    if (family != AF_UNSPEC && family != AF_INET) { trace_name("getaddrinfo (family)", node, family, 0, 0); return WSAEAFNOSUPPORT; }
    if ((flags & AI_CANONNAME) && !node) return WSAEINVAL;
    if (!ghbn || !inaddr) return WSANO_RECOVERY;
    if (service) {                                           /* port: number or service name */
        const char *e = service; unsigned long v = 0;
        while (*e >= '0' && *e <= '9' && v < 65536) v = v * 10 + (unsigned long)(*e++ - '0');
        if (*service && !*e && v < 65536) port = BS16(v);
        else if (flags & AI_NUMERICSERV) return WSAHOST_NOT_FOUND;
        else {
            struct servent *s = gsbn ? gsbn(service, socktype == SOCK_DGRAM ? "udp" : "tcp") : NULL;
            if (!s) return WSATYPE_NOT_FOUND;
            port = (USHORT)s->s_port;
        }
    }
    if (!node) addrs[naddr++] = (flags & AI_PASSIVE) ? 0 : BS32(0x7F000001UL);
    else {
        ULONG a = inaddr(node);
        if (a != INADDR_NONE || !strcmp(node, "255.255.255.255")) addrs[naddr++] = a;
        else if (flags & AI_NUMERICHOST) return WSAHOST_NOT_FOUND;
        else {
            struct hostent *h = ghbn(node);
            if (!h) { DWORD e0 = gle ? (DWORD)gle() : 0; if (!(h = dns_fallback(node))) SetLastError(e0); }
            if (!h) { rc = gle ? gle() : WSAHOST_NOT_FOUND; trace_name("getaddrinfo failed", node, rc, 0, 0);
                      return rc == WSATRY_AGAIN || rc == WSANO_RECOVERY || rc == WSANO_DATA ? rc : WSAHOST_NOT_FOUND; }
            if (h->h_addrtype != AF_INET || h->h_length != 4) return WSANO_DATA;
            for (i = 0; h->h_addr_list[i] && naddr < 35; i++) addrs[naddr++] = *(ULONG *)h->h_addr_list[i];
            canon = h->h_name;
        }
    }
    for (i = 0; i < naddr; i++) {
        int st, k, kinds = socktype ? 1 : 2;              /* no socket type given: one TCP and one UDP entry */
        for (k = 0; k < kinds; k++) {
            struct addrinfo *ai;
            st = socktype ? socktype : (k ? SOCK_DGRAM : SOCK_STREAM);
            ai = new_ai(addrs[i], port, st, proto ? proto : (st == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP));
            if (!ai) { kex_freeaddrinfo(head); return WSA_NOT_ENOUGH_MEMORY; }
            ai->ai_flags = flags;
            *tail = ai; tail = &ai->ai_next;
        }
    }
    if (head && (flags & AI_CANONNAME)) {
        const char *c = canon ? canon : node; int n = lstrlenA(c) + 1;
        if ((head->ai_canonname = (char *)HeapAlloc(GetProcessHeap(), 0, n))) lstrcpyA(head->ai_canonname, c);
    }
    *res = head;
    if (node) trace_name("getaddrinfo ok", node, naddr, naddr ? BS32(addrs[0]) : 0, flags);
    return 0;
}

INT KEXAPI kex_getnameinfo(const struct sockaddr *sa, socklen_t salen, PCHAR host, DWORD hostlen, PCHAR serv, DWORD servlen, INT flags)
{
    const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
    T_NTOA ntoa = (T_NTOA)ws("inet_ntoa"); T_GHBA ghba = (T_GHBA)ws("gethostbyaddr"); T_GSBP gsbp = (T_GSBP)ws("getservbyport");
    if (!sa || salen < (int)sizeof(*sin) || sin->sin_family != AF_INET) return WSAEAFNOSUPPORT;
    if (host && hostlen) {
        struct hostent *h = (!(flags & NI_NUMERICHOST) && ghba) ? ghba((const char *)&sin->sin_addr, 4, AF_INET) : NULL;
        const char *s = h ? h->h_name : (ntoa ? ntoa(sin->sin_addr) : NULL);
        if (!s) return (flags & NI_NAMEREQD) ? WSAHOST_NOT_FOUND : WSANO_RECOVERY;
        if (!h && (flags & NI_NAMEREQD)) return WSAHOST_NOT_FOUND;
        if ((DWORD)lstrlenA(s) >= hostlen) return WSAEFAULT;
        lstrcpyA(host, s);
    }
    if (serv && servlen) {
        struct servent *s = (!(flags & NI_NUMERICSERV) && gsbp) ? gsbp(sin->sin_port, (flags & NI_DGRAM) ? "udp" : "tcp") : NULL;
        char num[8]; int p = BS16(sin->sin_port), n = 0, d = 10000; BOOL lead = TRUE;
        if (s) { if ((DWORD)lstrlenA(s->s_name) >= servlen) return WSAEFAULT; lstrcpyA(serv, s->s_name); }
        else {
            for (; d; d /= 10) { int c = p / d % 10; if (c || !lead || d == 1) { num[n++] = (char)('0' + c); lead = FALSE; } }
            num[n] = 0;
            if ((DWORD)n >= servlen) return WSAEFAULT;
            lstrcpyA(serv, num);
        }
    }
    return 0;
}

/* ---- kexnt's own DNS client (2026-11-02). Mypal's lookups reach Windows 98's gethostbyname, which answers
 * WSAHOST_NOT_FOUND within 2 ms (no query on the wire) while PING and IE resolve the same names. Whatever
 * stops Winsock 2's name-space provider in that process, kexnt now asks the DNS servers itself when the
 * system lookup fails: one UDP "A" query (RFC 1035) to each server Windows knows (IPHLPAPI GetNetworkParams,
 * else the static MSTCP NameServer value), through the real WSOCK32 calls. Answers go into a per-thread
 * hostent, which is what gethostbyname callers expect. */
#include <iphlpapi.h>
typedef DWORD (WINAPI *T_GNP)(PFIXED_INFO, PULONG);
typedef int (WSAAPI *T_SENDTO)(SOCKET, const char *, int, int, const struct sockaddr *, int);
typedef int (WSAAPI *T_RECVFROM)(SOCKET, char *, int, int, struct sockaddr *, int *);
typedef int (WSAAPI *T_SELECT)(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
typedef int (WSAAPI *T_CLOSE)(SOCKET);
typedef SOCKET (WSAAPI *T_SOCK0)(int, int, int);
static FARPROC w1(int ord);

#define DNS_MAXADDR 8
typedef struct { struct hostent h; char *aliases[1]; char *list[DNS_MAXADDR + 1]; ULONG addr[DNS_MAXADDR]; char name[256]; } DNSHE;
#define DNS_RING 64
static DNSHE *volatile g_dns_ring;

static ULONG parse_ip(const char *s, const char **end)
{
    ULONG v = 0; int part, i;
    for (i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9') return 0;
        for (part = 0; *s >= '0' && *s <= '9'; s++) { part = part * 10 + (*s - '0'); if (part > 255) return 0; }
        v |= (ULONG)part << (8 * i);                     /* network order in memory */
        if (i < 3) { if (*s != '.') return 0; s++; }
    }
    if (end) *end = s;
    return v;
}

static int dns_servers(ULONG *out, int max)
{
    int n = 0;
    T_GNP gnp = (T_GNP)(void *)kex_sysproc("IPHLPAPI.DLL", "GetNetworkParams");
    if (gnp) {
        ULONG len = 0; PFIXED_INFO fi;
        gnp(NULL, &len);
        if (len && len < 65536 && (fi = (PFIXED_INFO)HeapAlloc(GetProcessHeap(), 0, len))) {
            if (gnp(fi, &len) == ERROR_SUCCESS) {
                PIP_ADDR_STRING a;
                for (a = &fi->DnsServerList; a && n < max; a = a->Next) {
                    ULONG ip = parse_ip(a->IpAddress.String, NULL);
                    if (ip) out[n++] = ip;
                }
            }
            HeapFree(GetProcessHeap(), 0, fi);
        }
    }
    if (!n) {                                            /* static servers: "a.b.c.d,e.f.g.h" */
        HKEY k; char buf[256]; DWORD cb = sizeof(buf) - 1, t;
        if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\VxD\\MSTCP", 0, KEY_READ, &k)) {
            if (!RegQueryValueExA(k, "NameServer", NULL, &t, (BYTE *)buf, &cb)) {
                const char *p = buf; buf[cb] = 0;
                while (*p && n < max) {
                    const char *e; ULONG ip = parse_ip(p, &e);
                    if (ip) { out[n++] = ip; p = e; } else p++;
                    while (*p == ',' || *p == ' ') p++;
                }
            }
            RegCloseKey(k);
        }
    }
    return n;
}

/* skip a (possibly compressed) name in a DNS message; returns new offset or -1 */
static int dns_skip(const unsigned char *m, int len, int o)
{
    int hops = 0;
    while (o < len) {
        int c = m[o];
        if (!c) return o + 1;
        if ((c & 0xC0) == 0xC0) return o + 2 <= len ? o + 2 : -1;
        if (c & 0xC0 || ++hops > 128) return -1;
        o += c + 1;
    }
    return -1;
}

/* one A lookup; fills addr[] (network order), returns count, 0 = not found, -1 = no answer at all */
static int dns_query(const char *name, ULONG *addr, int max, DWORD *server_used)
{
    T_SOCK0 sk = (T_SOCK0)(void *)w1(23); T_SENDTO st = (T_SENDTO)(void *)w1(20); T_RECVFROM rf = (T_RECVFROM)(void *)w1(17);
    T_SELECT sel = (T_SELECT)(void *)w1(18); T_CLOSE cl = (T_CLOSE)(void *)w1(3);
    unsigned char q[300], r[1500]; int ql = 12, nl, ns, srv, tries, result = -1;
    ULONG servers[4]; USHORT id = (USHORT)(GetTickCount() ^ (GetCurrentThreadId() << 3));
    const char *p = name; SOCKET s;
    if (!sk || !st || !rf || !sel || !cl) return -1;
    nl = lstrlenA(name);
    if (!nl || nl > 253) return 0;
    memset(q, 0, 12); q[0] = (unsigned char)(id >> 8); q[1] = (unsigned char)id; q[2] = 0x01; q[5] = 1;   /* RD, QDCOUNT 1 */
    while (*p) {                                         /* labels */
        const char *e = p; int l;
        while (*e && *e != '.') e++;
        l = (int)(e - p);
        if (l < 1 || l > 63) { if (!l && !*e) break; return 0; }
        q[ql++] = (unsigned char)l; memcpy(q + ql, p, l); ql += l;
        p = *e ? e + 1 : e;
    }
    q[ql++] = 0; q[ql++] = 0; q[ql++] = 1; q[ql++] = 0; q[ql++] = 1;     /* QTYPE A, QCLASS IN */
    ns = dns_servers(servers, 4);
    kex_trace("dns: servers", (DWORD)ns, ns ? BS32(servers[0]) : 0, ns > 1 ? BS32(servers[1]) : 0, 0);
    if (!ns) return -1;
    s = sk(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { kex_trace("dns: no UDP socket", 0, 0, 0, 0); return -1; }
    for (tries = 0; tries < 2 && result < 0; tries++)
        for (srv = 0; srv < ns && result < 0; srv++) {
            struct sockaddr_in to; fd_set fs; struct timeval tv; DWORD t0 = GetTickCount();
            memset(&to, 0, sizeof(to)); to.sin_family = AF_INET; to.sin_port = BS16(53); to.sin_addr.s_addr = servers[srv];
            if (st(s, (const char *)q, ql, 0, (struct sockaddr *)&to, sizeof(to)) != ql) continue;
            for (;;) {
                struct sockaddr_in from; int fl = sizeof(from), n, o, an, qd, k, rc;
                DWORD el = GetTickCount() - t0;
                if (el >= 2000) break;
                FD_ZERO(&fs); FD_SET(s, &fs); tv.tv_sec = (long)(2000 - el) / 1000; tv.tv_usec = (long)((2000 - el) % 1000) * 1000;
                if (sel(0, &fs, NULL, NULL, &tv) <= 0) break;
                n = rf(s, (char *)r, sizeof(r), 0, (struct sockaddr *)&from, &fl);
                if (n < 12 || r[0] != q[0] || r[1] != q[1] || !(r[2] & 0x80)) continue;   /* not our answer */
                rc = r[3] & 15;
                if (server_used) *server_used = BS32(servers[srv]);
                if (rc == 3) { result = 0; break; }                                     /* NXDOMAIN */
                if (rc) break;                                                          /* SERVFAIL etc: next server */
                qd = (r[4] << 8) | r[5]; an = (r[6] << 8) | r[7]; o = 12;
                for (k = 0; k < qd && o > 0; k++) { o = dns_skip(r, n, o); if (o > 0) o += 4; }
                result = 0;
                for (k = 0; k < an && o > 0 && o < n; k++) {
                    int type, cls, rdl;
                    o = dns_skip(r, n, o);
                    if (o < 0 || o + 10 > n) break;
                    type = (r[o] << 8) | r[o + 1]; cls = (r[o + 2] << 8) | r[o + 3]; rdl = (r[o + 8] << 8) | r[o + 9];
                    o += 10;
                    if (o + rdl > n) break;
                    if (type == 1 && cls == 1 && rdl == 4 && result < max) memcpy(&addr[result++], r + o, 4);
                    o += rdl;
                }
                break;
            }
        }
    cl(s);
    return result;
}

/* names Windows would answer without DNS: "localhost" and the HOSTS file (%windir%\HOSTS on Windows 98) */
static int ieq(const char *a, const char *b, int n)
{
    int i;
    for (i = 0; i < n; i++) { char x = a[i], y = b[i]; if (x >= 'A' && x <= 'Z') x += 32; if (y >= 'A' && y <= 'Z') y += 32; if (x != y) return 0; }
    return 1;
}
static int hosts_lookup(const char *name, ULONG *addr, int max)
{
    char path[MAX_PATH], *buf, *p, *end; HANDLE f; DWORD size, rd = 0; int n = 0, nl = lstrlenA(name);
    if (!lstrcmpiA(name, "localhost")) { addr[0] = BS32(0x7F000001UL); return 1; }
    if (!GetWindowsDirectoryA(path, MAX_PATH - 8)) return 0;
    lstrcatA(path, "\\HOSTS");
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    size = GetFileSize(f, NULL);
    if (size == 0xFFFFFFFF || size > 1024 * 1024 || !(buf = (char *)HeapAlloc(GetProcessHeap(), 0, size + 1))) { CloseHandle(f); return 0; }
    ReadFile(f, buf, size, &rd, NULL); CloseHandle(f); buf[rd] = 0;
    for (p = buf; *p && n < max; ) {
        char *line = p; ULONG ip; const char *e;
        while (*p && *p != '\n') p++;
        end = p; if (*p) p++;
        while (line < end && (*line == ' ' || *line == '\t')) line++;
        if (line >= end || *line == '#' || !(ip = parse_ip(line, &e))) continue;
        line = (char *)e;
        while (line < end && *line != '#') {
            char *w;
            while (line < end && (*line == ' ' || *line == '\t' || *line == '\r')) line++;
            w = line;
            while (line < end && *line != ' ' && *line != '\t' && *line != '\r' && *line != '#') line++;
            if (line - w == nl && ieq(w, name, nl)) { addr[n++] = ip; break; }
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return n;
}

/* one-time clue: which name-space providers Winsock 2 itself reports in this process */
typedef INT (WSAAPI *T_ENUMNS)(LPDWORD, LPWSANAMESPACE_INFOA);
static void ns_diag(void)
{
    T_ENUMNS en = (T_ENUMNS)(void *)ws("WSAEnumNameSpaceProvidersA");
    DWORD len = 0; int n, i; BYTE *buf; LPWSANAMESPACE_INFOA ni;
    if (!en) { kex_trace("dns: no WSAEnumNameSpaceProvidersA", 0, 0, 0, 0); return; }
    n = en(&len, NULL);
    if (len == 0 || len > 65536 || !(buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len))) {
        T_WSAGLE gle = (T_WSAGLE)ws("WSAGetLastError");
        kex_trace("dns: name-space providers: none (n len err)", (DWORD)n, len, gle ? (DWORD)gle() : 0, 0); return;
    }
    n = en(&len, (LPWSANAMESPACE_INFOA)buf);
    kex_trace("dns: name-space providers n len", (DWORD)n, len, 0, 0);
    for (ni = (LPWSANAMESPACE_INFOA)buf, i = 0; i < n && i < 8; i++, ni++)
        trace_name("dns: provider", ni->lpszIdentifier && !IsBadStringPtrA(ni->lpszIdentifier, 64) ? ni->lpszIdentifier : "?",
                   ni->dwNameSpace, (DWORD)ni->fActive, ni->dwVersion);
    HeapFree(GetProcessHeap(), 0, buf);
}

static struct hostent *dns_fallback(const char *name)
{
    DNSHE *e; int n, i; DWORD srv = 0;
    static LONG next, diag;
    if (!name || !*name || parse_ip(name, NULL)) return NULL;
    if (!InterlockedExchange(&diag, 1)) ns_diag();
    /* a ring of answers instead of a TLS slot (Mypal had used up all native slots): a gethostbyname
     * result only has to live until that thread's next lookup, and callers copy it at once */
    if (!g_dns_ring && !(g_dns_ring = (DNSHE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DNSHE) * DNS_RING))) return NULL;
    e = &g_dns_ring[(DWORD)InterlockedIncrement(&next) % DNS_RING];
    n = hosts_lookup(name, e->addr, DNS_MAXADDR);
    if (n > 0) srv = 0xFFFFFFFFUL;                       /* answered from the HOSTS file */
    else n = dns_query(name, e->addr, DNS_MAXADDR, &srv);
    trace_name("dns: kexnt lookup", name, (DWORD)n, n > 0 ? BS32(e->addr[0]) : 0, srv);
    if (n <= 0) return NULL;
    lstrcpynA(e->name, name, sizeof(e->name));
    for (i = 0; i < n; i++) e->list[i] = (char *)&e->addr[i];
    e->list[n] = NULL; e->aliases[0] = NULL;
    e->h.h_name = e->name; e->h.h_aliases = e->aliases; e->h.h_addrtype = AF_INET; e->h.h_length = 4; e->h.h_addr_list = e->list;
    SetLastError(0);
    return &e->h;
}

/* exported for KEXTEST: kexnt's own lookup of one name, IPv4 address in host order (0 = none) */
DWORD KEXAPI kex_KexDnsLookup(const char *name)
{
    ULONG a[DNS_MAXADDR]; DWORD srv = 0; int n = dns_query(name, a, DNS_MAXADDR, &srv);
    return n > 0 ? BS32(a[0]) : 0;
}

/* ---- tracing pass-throughs for the classic Winsock calls (2026-11-02, round after "nope mypal does not work").
 * NSPR inside Mypal's nss3.dll imports WSOCK32 by ordinal and, with no IPv6 (Win98), resolves names with
 * PR_GetHostByName -> WSOCK32 #52 gethostbyname, never getaddrinfo. These wrappers call the real functions
 * unchanged and only leave a line in KEXTRACE_<program>.LOG, so the next run shows whether a lookup and a
 * connection happen and what Windows answers. Routed by ordinal (kexnt_targets.txt "WSOCK32@52"). */
typedef int (WSAAPI *T_WSAST)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *T_SOCK)(int, int, int);
typedef int (WSAAPI *T_CONN)(SOCKET, const struct sockaddr *, int);

void kex_prof_net(int kind, LONG bytes, unsigned __int64 cyc);
void kex_prof_sock(int kind, SOCKET s, LONG v);
LONG kex_prof_enabled(void);
static FARPROC w1(int ord) { return kex_sysproc("WSOCK32.DLL", (LPCSTR)(ULONG_PTR)ord); }   /* real WSOCK32 by number */
static LONG g_ws_socks, g_ws_conns;

static struct hostent *ghbn_traced(const char *tag, T_GHBN real, T_WSAGLE gle, const char *name)
{
    struct hostent *h; DWORD t0 = GetTickCount();
    if (!real) { trace_name(tag, name, 0xDEAD, 0, 0); return NULL; }
    h = real(name);
    if (kex_prof_enabled()) kex_prof_sock(5, 0, (LONG)(GetTickCount() - t0));
    if (!h) {
        DWORD err = gle ? (DWORD)gle() : 0;
        trace_name(tag, name, 0, err, 0);
        if ((h = dns_fallback(name))) return h;
        SetLastError(err);
    }
    else trace_name(tag, name, 1, (h->h_addr_list && h->h_addr_list[0]) ? BS32(*(ULONG *)h->h_addr_list[0]) : 0, (DWORD)h->h_addrtype);
    return h;
}

struct hostent *KEXAPI kex_ws1_gethostbyname(const char *name)
{ return ghbn_traced("wsock32 gethostbyname", (T_GHBN)w1(52), (T_WSAGLE)w1(111), name); }

struct hostent *KEXAPI kex_gethostbyname(const char *name)
{ return ghbn_traced("ws2_32 gethostbyname", (T_GHBN)ws("gethostbyname"), (T_WSAGLE)ws("WSAGetLastError"), name); }

int KEXAPI kex_ws1_WSAStartup(WORD ver, LPWSADATA d)
{
    T_WSAST real = (T_WSAST)w1(115); int rc = real ? real(ver, d) : WSASYSNOTREADY;
    kex_trace("wsock32 WSAStartup", ver, (DWORD)rc, 0, 0);
    return rc;
}

/* Universal TCP tuning (2026-11-02): Windows 98 advertises an 8 KB receive window by default (MSTCP
 * DefaultRcvWindow), which caps one connection at 8 KB per round trip. Every TCP socket a KernelEx program
 * opens gets a 64 KB receive buffer instead (SO_RCVBUF, honoured per socket by MSTCP). KexNG "TcpRcvBuf"
 * (bytes, 0 = leave Windows' default) overrides the size. */
typedef int (WSAAPI *T_SSO)(SOCKET, int, int, const char *, int);
static void tcp_tune(SOCKET s)
{
    static LONG size = -1; static T_SSO sso;
    LONG v = size;
    if (v < 0) {
        HKEY k; DWORD t, n = sizeof(DWORD), d = 65536;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "TcpRcvBuf", NULL, &t, (BYTE *)&d, &n) != ERROR_SUCCESS || t != REG_DWORD) d = 65536;
            RegCloseKey(k);
        }
        if (d > 0x100000) d = 0x100000;
        size = v = (LONG)d;
    }
    if (!v) return;
    if (!sso) sso = (T_SSO)(void *)w1(21);
    if (sso) { DWORD le = GetLastError(); sso(s, SOL_SOCKET, SO_RCVBUF, (const char *)&v, sizeof(v)); SetLastError(le); }
}

static SOCKET sock_traced(const char *tag, T_SOCK real, T_WSAGLE gle, int af, int type, int proto)
{
    SOCKET s = real ? real(af, type, proto) : INVALID_SOCKET;
    if (s != INVALID_SOCKET && type == SOCK_STREAM) tcp_tune(s);
    if (InterlockedIncrement(&g_ws_socks) <= 300)
        kex_trace(tag, (DWORD)af | ((DWORD)type << 16), (DWORD)proto, (DWORD)s, s == INVALID_SOCKET && gle ? (DWORD)gle() : 0);
    return s;
}
SOCKET KEXAPI kex_ws1_socket(int af, int type, int proto) { return sock_traced("wsock32 socket af|type<<16 proto -> s err", (T_SOCK)w1(23), (T_WSAGLE)w1(111), af, type, proto); }

static int conn_traced(const char *tag, T_CONN real, T_WSAGLE gle, SOCKET s, const struct sockaddr *sa, int len)
{
    int rc = real ? real(s, sa, len) : SOCKET_ERROR;
    DWORD err = rc && gle ? (DWORD)gle() : 0;          /* keep the error for the caller: trace doesn't touch it, set it back */
    if (kex_prof_enabled()) { kex_prof_sock(3, s, 0); if (rc) SetLastError(err); }
    if (InterlockedIncrement(&g_ws_conns) <= 300) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        kex_trace(tag, (DWORD)s, sin && len >= 8 ? BS32(sin->sin_addr.s_addr) : 0,
                  sin && len >= 8 ? ((DWORD)BS16(sin->sin_port) | ((DWORD)sin->sin_family << 16)) : 0, err);
        if (rc) SetLastError(err);
    }
    return rc;
}
int KEXAPI kex_ws1_connect(SOCKET s, const struct sockaddr *sa, int len) { return conn_traced("wsock32 connect s ip port|af<<16 err", (T_CONN)w1(4), (T_WSAGLE)w1(111), s, sa, len); }

/* recv / send / select pass-throughs, counted for the profiler (prof_ext.c) - WSOCK32 #16, #19, #18 */
typedef int (WSAAPI *T_RS)(SOCKET, char *, int, int);
typedef int (WSAAPI *T_SEL)(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
int KEXAPI kex_ws1_recv(SOCKET s, char *b, int n, int f)
{ static T_RS r; int x; if (!r) r = (T_RS)(void *)w1(16); x = r ? r(s, b, n, f) : SOCKET_ERROR; if (kex_prof_enabled()) { DWORD le = GetLastError(); kex_prof_net(0, x, 0); kex_prof_sock(0, s, x); SetLastError(le); } return x; }
int KEXAPI kex_ws1_send(SOCKET s, const char *b, int n, int f)
{ static T_RS r; int x; if (!r) r = (T_RS)(void *)w1(19); x = r ? r(s, (char *)b, n, f) : SOCKET_ERROR; if (kex_prof_enabled()) { DWORD le = GetLastError(); kex_prof_net(1, x, 0); kex_prof_sock(1, s, x); SetLastError(le); } return x; }
int KEXAPI kex_ws1_select(int nfds, fd_set *rd, fd_set *wr, fd_set *ex, const struct timeval *tv)
{
    static T_SEL r; int x; unsigned __int64 t0;
    if (!r) r = (T_SEL)(void *)w1(18);
    if (!r) return SOCKET_ERROR;
    if (!kex_prof_enabled()) return r(nfds, rd, wr, ex, tv);
    t0 = __rdtsc(); x = r(nfds, rd, wr, ex, tv);
    { DWORD le = GetLastError(); kex_prof_net(2, 0, __rdtsc() - t0); SetLastError(le); }
    return x;
}

/* closesocket (WSOCK32 #3): ends the profiler's record of the connection */
typedef int (WSAAPI *T_CLS)(SOCKET);
int KEXAPI kex_ws1_closesocket(SOCKET s)
{ static T_CLS r; if (!r) r = (T_CLS)(void *)w1(3); if (kex_prof_enabled()) kex_prof_sock(4, s, 0); return r ? r(s) : SOCKET_ERROR; }

/* ---- Winsock 2 calls Chromium's network thread makes (build 26): traced pass-throughs.
 * The NetLog of build 25 stopped 0.4 s after Chromium's first QUIC (UDP) socket connected: no event for any
 * request after that, typed addresses never reached DNS - the network thread itself seems stuck inside a
 * Winsock call. Each call below writes "ws2 <name> >" before and "ws2 <name> <" after (result, error, ms), so a
 * call that never returns is the last ">" line of its thread. The first 300 calls of each kind are traced;
 * calls that take 200 ms or longer are always traced. */
typedef int (WSAAPI *T_WRF)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr *, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *T_WSTO)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr *, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *T_WR)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *T_WS)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *T_WGOR)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
typedef int (WSAAPI *T_WES)(SOCKET, HANDLE, long);
typedef int (WSAAPI *T_WENE)(SOCKET, HANDLE, LPWSANETWORKEVENTS);
typedef SOCKET (WSAAPI *T_WSOCKW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);

#define WSTRACE_N 300
static int ws_t_enter(volatile LONG *cnt, const char *nm, DWORD a, DWORD b, DWORD c, DWORD d)
{
    char line[64]; int on = InterlockedIncrement((LONG *)cnt) <= WSTRACE_N;
    if (on) { lstrcpyA(line, "ws2 "); lstrcatA(line, nm); lstrcatA(line, " >"); kex_trace(line, a, b, c, d); }
    return on;
}
static void ws_t_leave(int on, const char *nm, DWORD r, DWORD err, DWORD t0, DWORD extra)
{
    DWORD ms = GetTickCount() - t0;
    if (on || ms >= 200) {
        char line[64]; lstrcpyA(line, "ws2 "); lstrcatA(line, nm); lstrcatA(line, " < (ret err ms x)");
        kex_trace(line, r, err, ms, extra);
    }
}
#define WS_ERR() (((T_WSAGLE)ws("WSAGetLastError"))())
#define WS_SETERR(e) do { typedef void (WSAAPI *T_WSLE)(int); ((T_WSLE)ws("WSASetLastError"))(e); } while (0)

int KEXAPI kex_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD got, LPDWORD fl, struct sockaddr *from, LPINT fromlen,
                           LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    static T_WRF f; static volatile LONG n; int on, r, e; DWORD t0 = GetTickCount();
    if (!f) f = (T_WRF)ws("WSARecvFrom");
    on = ws_t_enter(&n, "WSARecvFrom", (DWORD)s, nb ? b->len : 0, (DWORD)(ULONG_PTR)ov, (DWORD)(ULONG_PTR)cr); t0 = GetTickCount();
    r = f(s, b, nb, got, fl, from, fromlen, ov, cr); e = r ? WS_ERR() : 0;
    ws_t_leave(on, "WSARecvFrom", (DWORD)r, (DWORD)e, t0, got ? *got : 0);
    if (r) WS_SETERR(e);
    return r;
}
int KEXAPI kex_WSASendTo(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD fl, const struct sockaddr *to, int tolen,
                         LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    static T_WSTO f; static volatile LONG n; int on, r, e; DWORD t0 = GetTickCount();
    if (!f) f = (T_WSTO)ws("WSASendTo");
    on = ws_t_enter(&n, "WSASendTo", (DWORD)s, nb ? b->len : 0, (DWORD)(ULONG_PTR)ov, (DWORD)(ULONG_PTR)cr); t0 = GetTickCount();
    r = f(s, b, nb, sent, fl, to, tolen, ov, cr); e = r ? WS_ERR() : 0;
    ws_t_leave(on, "WSASendTo", (DWORD)r, (DWORD)e, t0, sent ? *sent : 0);
    if (r) WS_SETERR(e);
    return r;
}
int KEXAPI kex_WSARecv(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD got, LPDWORD fl, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    static T_WR f; static volatile LONG n; int on, r, e; DWORD t0 = GetTickCount();
    if (!f) f = (T_WR)ws("WSARecv");
    on = ws_t_enter(&n, "WSARecv", (DWORD)s, nb ? b->len : 0, (DWORD)(ULONG_PTR)ov, (DWORD)(ULONG_PTR)cr); t0 = GetTickCount();
    r = f(s, b, nb, got, fl, ov, cr); e = r ? WS_ERR() : 0;
    ws_t_leave(on, "WSARecv", (DWORD)r, (DWORD)e, t0, got ? *got : 0);
    if (r) WS_SETERR(e);
    return r;
}
int KEXAPI kex_WSASend(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD fl, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    static T_WS f; static volatile LONG n; int on, r, e; DWORD t0 = GetTickCount();
    if (!f) f = (T_WS)ws("WSASend");
    on = ws_t_enter(&n, "WSASend", (DWORD)s, nb ? b->len : 0, (DWORD)(ULONG_PTR)ov, (DWORD)(ULONG_PTR)cr); t0 = GetTickCount();
    r = f(s, b, nb, sent, fl, ov, cr); e = r ? WS_ERR() : 0;
    ws_t_leave(on, "WSASend", (DWORD)r, (DWORD)e, t0, sent ? *sent : 0);
    if (r) WS_SETERR(e);
    return r;
}
BOOL KEXAPI kex_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED ov, LPDWORD n, BOOL wait, LPDWORD fl)
{
    static T_WGOR f; static volatile LONG c; int on, e; BOOL r; DWORD t0 = GetTickCount();
    if (!f) f = (T_WGOR)ws("WSAGetOverlappedResult");
    on = ws_t_enter(&c, "WSAGetOverlappedResult", (DWORD)s, (DWORD)(ULONG_PTR)ov, wait, 0); t0 = GetTickCount();
    r = f(s, ov, n, wait, fl); e = r ? 0 : WS_ERR();
    ws_t_leave(on, "WSAGetOverlappedResult", (DWORD)r, (DWORD)e, t0, n ? *n : 0);
    if (!r) WS_SETERR(e);
    return r;
}
int KEXAPI kex_WSAEventSelect(SOCKET s, HANDLE ev, long mask)
{
    static T_WES f; static volatile LONG c; int on, r, e; DWORD t0 = GetTickCount();
    if (!f) f = (T_WES)ws("WSAEventSelect");
    on = ws_t_enter(&c, "WSAEventSelect", (DWORD)s, (DWORD)(ULONG_PTR)ev, (DWORD)mask, 0); t0 = GetTickCount();
    r = f(s, ev, mask); e = r ? WS_ERR() : 0;
    ws_t_leave(on, "WSAEventSelect", (DWORD)r, (DWORD)e, t0, 0);
    if (r) WS_SETERR(e);
    return r;
}
int KEXAPI kex_WSAEnumNetworkEvents(SOCKET s, HANDLE ev, LPWSANETWORKEVENTS ne)
{
    static T_WENE f; static volatile LONG c; int on, r, e; DWORD t0 = GetTickCount();
    if (!f) f = (T_WENE)ws("WSAEnumNetworkEvents");
    on = ws_t_enter(&c, "WSAEnumNetworkEvents", (DWORD)s, (DWORD)(ULONG_PTR)ev, 0, 0); t0 = GetTickCount();
    r = f(s, ev, ne); e = r ? WS_ERR() : 0;
    ws_t_leave(on, "WSAEnumNetworkEvents", (DWORD)r, (DWORD)e, t0, (!r && ne) ? (DWORD)ne->lNetworkEvents : 0);
    if (r) WS_SETERR(e);
    return r;
}
/* Win98's WS2_32 has no IPv6 provider. Asked for an AF_INET6 socket, WSASocketW does not fail: it never
 * returns (seen with Chromium's IPv6 reachability probe, which then stalls the whole network thread).
 * So every family other than AF_INET is refused here at once with WSAEAFNOSUPPORT, like Windows does
 * when no provider for the family is installed; the caller then simply treats IPv6 as unavailable.
 * Without protocol info the call goes through WSASocketA, the path every Win98 program uses. */
typedef SOCKET (WSAAPI *T_WSOCKA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
static int ws_family_ok(int af) { return af == AF_INET || af == AF_UNSPEC; }
SOCKET KEXAPI kex_WSASocketW(int af, int type, int proto, LPWSAPROTOCOL_INFOW pi, GROUP g, DWORD fl)
{
    static T_WSOCKW f; static T_WSOCKA fa; static volatile LONG c; int on, e; SOCKET r; DWORD t0 = GetTickCount();
    if (!f) f = (T_WSOCKW)ws("WSASocketW");
    if (!fa) fa = (T_WSOCKA)ws("WSASocketA");
    on = ws_t_enter(&c, "WSASocketW", (DWORD)af, (DWORD)type, (DWORD)proto, fl); t0 = GetTickCount();
    if (!ws_family_ok(af) || (pi && !ws_family_ok(pi->iAddressFamily))) { r = INVALID_SOCKET; e = WSAEAFNOSUPPORT; }
    else {
        r = (!pi && fa) ? fa(af, type, proto, NULL, g, fl) : f(af, type, proto, pi, g, fl);
        e = (r == INVALID_SOCKET) ? WS_ERR() : 0;
        if (r != INVALID_SOCKET && type == SOCK_STREAM) tcp_tune(r);
    }
    ws_t_leave(on, "WSASocketW", (DWORD)r, (DWORD)e, t0, 0);
    if (e) WS_SETERR(e);
    return r;
}
SOCKET KEXAPI kex_WSASocketA(int af, int type, int proto, LPWSAPROTOCOL_INFOA pi, GROUP g, DWORD fl)
{
    static T_WSOCKA fa; static volatile LONG c; int on, e; SOCKET r; DWORD t0 = GetTickCount();
    if (!fa) fa = (T_WSOCKA)ws("WSASocketA");
    on = ws_t_enter(&c, "WSASocketA", (DWORD)af, (DWORD)type, (DWORD)proto, fl); t0 = GetTickCount();
    if (!ws_family_ok(af) || (pi && !ws_family_ok(pi->iAddressFamily)) || !fa) { r = INVALID_SOCKET; e = WSAEAFNOSUPPORT; }
    else { r = fa(af, type, proto, pi, g, fl); e = (r == INVALID_SOCKET) ? WS_ERR() : 0; }
    ws_t_leave(on, "WSASocketA", (DWORD)r, (DWORD)e, t0, 0);
    if (e) WS_SETERR(e);
    return r;
}
/* WS2_32 socket (ordinal 23), which Chromium imports by number: same family rule. */
SOCKET KEXAPI kex_ws2_socket(int af, int type, int proto)
{
    static T_SOCK f; static volatile LONG c; int on, e; SOCKET r; DWORD t0 = GetTickCount();
    if (!f) f = (T_SOCK)ws("socket");
    on = ws_t_enter(&c, "socket", (DWORD)af, (DWORD)type, (DWORD)proto, 0); t0 = GetTickCount();
    if (!ws_family_ok(af) || !f) { r = INVALID_SOCKET; e = WSAEAFNOSUPPORT; }
    else {
        r = f(af, type, proto); e = (r == INVALID_SOCKET) ? WS_ERR() : 0;
        if (r != INVALID_SOCKET && type == SOCK_STREAM) tcp_tune(r);
    }
    ws_t_leave(on, "socket", (DWORD)r, (DWORD)e, t0, 0);
    if (e) WS_SETERR(e);
    return r;
}

/* build 129: getsockname on a CONNECTED UDP socket. Chromium finds "the address this machine uses for the internet"
 * by connecting a UDP socket to a public address and asking getsockname (P2P GetDefaultLocalAddress, used by WebRTC
 * when it may not list the network adapters). Windows 9x answers 0.0.0.0 there (the address is only chosen when a
 * datagram is sent). A build-128 Discord voice connection then had no IPv4 port at all (only a failing IPv6 one)
 * and stayed at "RTC Connecting", while the stream connection - made later, with the adapter list - connected.
 * When Windows says 0.0.0.0 for a socket that has a peer, the address of the adapter that reaches the peer is filled
 * in (same subnet, else the adapter with a gateway, else the first one with an address). */
#include <iphlpapi.h>
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
typedef int (WSAAPI *T_GSN)(SOCKET, struct sockaddr *, int *);
typedef DWORD (WINAPI *T_GAI2)(PIP_ADAPTER_INFO, PULONG);
static ULONG ip4(const char *s) { typedef unsigned long (WSAAPI *T)(const char *); T f = (T)ws("inet_addr"); ULONG a = f ? f(s) : INADDR_NONE; return a == INADDR_NONE ? 0 : a; }
static ULONG route_addr(ULONG peer)
{
    T_GAI2 gai = (T_GAI2)(void *)kex_sysproc("IPHLPAPI.DLL", "GetAdaptersInfo");
    ULONG sz = 0, best = 0, gw = 0, any = 0; IP_ADAPTER_INFO *ai, *p;
    if (!gai || gai(NULL, &sz) != ERROR_BUFFER_OVERFLOW || !sz) return 0;
    if (!(ai = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, sz + 64))) return 0;
    if (gai(ai, &sz) == ERROR_SUCCESS)
        for (p = ai; p; p = p->Next) {
            IP_ADDR_STRING *a;
            for (a = &p->IpAddressList; a; a = a->Next) {
                ULONG ad = ip4(a->IpAddress.String), m = ip4(a->IpMask.String);
                if (!ad) continue;
                if (!any) any = ad;
                if (!gw && ip4(p->GatewayList.IpAddress.String)) gw = ad;
                if (!best && m && (ad & m) == (peer & m)) best = ad;
            }
        }
    HeapFree(GetProcessHeap(), 0, ai);
    return best ? best : gw ? gw : any;
}
static int gsn_fix(T_GSN f, T_GSN fpeer, SOCKET s, struct sockaddr *sa, int *len)
{
    int r = f(s, sa, len);
    if (!r && sa && len && *len >= (int)sizeof(struct sockaddr_in) && sa->sa_family == AF_INET &&
        ((struct sockaddr_in *)sa)->sin_addr.s_addr == 0 && fpeer) {
        struct sockaddr_in peer; int pl = sizeof(peer); int le = WS_ERR();
        if (!fpeer(s, (struct sockaddr *)&peer, &pl) && peer.sin_family == AF_INET && peer.sin_addr.s_addr) {
            ULONG me = route_addr(peer.sin_addr.s_addr);
            if (me) {
                ((struct sockaddr_in *)sa)->sin_addr.s_addr = me;
                {   static LONG k; if (InterlockedIncrement(&k) <= 10)
                        kex_crashnote("getsockname on a connected socket: Windows said 0.0.0.0, the adapter's address given (socket, address, peer, port)",
                                      (DWORD)s, me, peer.sin_addr.s_addr, ((struct sockaddr_in *)sa)->sin_port); }
            }
        }
        WS_SETERR(le);
    }
    return r;
}
int KEXAPI kex_ws2_getsockname(SOCKET s, struct sockaddr *sa, int *len)
{
    static T_GSN f, fp;
    if (!f) f = (T_GSN)ws("getsockname");
    if (!fp) fp = (T_GSN)ws("getpeername");
    if (!f) { WS_SETERR(WSAENOTSOCK); return SOCKET_ERROR; }
    return gsn_fix(f, fp, s, sa, len);
}

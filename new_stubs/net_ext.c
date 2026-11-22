/*
 * net_ext.c - KernelEx-NG build 128: GetAdaptersAddresses (and if_indextoname / if_nametoindex) on Windows 98.
 *
 * Why. kexnt answered GetAdaptersAddresses with ERROR_NO_DATA (build 30 stub). Chromium's WebRTC (network manager)
 * and net::GetNetworkList build their list of local networks from it: with none, a peer connection has no local
 * address to gather ICE candidates from, so it never connects - Discord voice stayed at "RTC Connecting" (build 127
 * user report). Chrome's DNS config reader also reads its name servers from here ("Failed to read DnsConfig").
 *
 * What. Windows 98 SE's IPHLPAPI.DLL has GetAdaptersInfo (IPv4 adapters with addresses, masks, gateways, MAC) and
 * GetNetworkParams (DNS servers). Each adapter that has an address becomes one IP_ADAPTER_ADDRESSES (Vista layout,
 * the caller's SDK decides how much it reads; Length tells it) with its unicast addresses (prefix length from the
 * mask), gateways (GAA_FLAG_INCLUDE_GATEWAYS) and DNS servers, status Up, IPv4 enabled. IPv6 (AF_INET6): no data,
 * as on a machine without IPv6. The loopback interface is not listed (Windows 98 has none in GetAdaptersInfo).
 */
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "kexnt_common.h"

typedef DWORD (WINAPI *T_GAI)(PIP_ADAPTER_INFO, PULONG);
typedef DWORD (WINAPI *T_GNP)(PFIXED_INFO, PULONG);

static ULONG a4(const char *s)                /* dotted quad -> network order; 0 if not one */
{
    ULONG v = 0, part = 0; int dots = 0, digits = 0;
    for (;; s++) {
        if (*s >= '0' && *s <= '9') { part = part * 10 + (*s - '0'); digits++; if (part > 255) return 0; }
        else if (*s == '.' || !*s) {
            if (!digits) return 0;
            v |= part << (8 * dots); part = 0; digits = 0;
            if (!*s) break;
            if (++dots > 3) return 0;
        } else return 0;
    }
    return dots == 3 ? v : 0;
}
static UINT8 prefix_len(ULONG mask_net)
{
    ULONG m = ((mask_net & 0xFF) << 24) | ((mask_net & 0xFF00) << 8) | ((mask_net >> 8) & 0xFF00) | (mask_net >> 24);
    UINT8 n = 0;
    while (m & 0x80000000UL) { n++; m <<= 1; }
    return n;
}
/* a bump allocator over the caller's buffer (or a counting pass with no buffer) */
typedef struct { BYTE *p; ULONG used, cap; } BUMP;
static void *take(BUMP *b, ULONG n)
{
    void *r = NULL;
    b->used = (b->used + 7) & ~7UL;
    if (b->p && b->used + n <= b->cap) { r = b->p + b->used; ZeroMemory(r, n); }
    b->used += n;
    return r;
}
static WCHAR *wdup(BUMP *b, const char *s)
{
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0); WCHAR *w;
    if (n <= 0) n = 1;
    w = (WCHAR *)take(b, n * sizeof(WCHAR));
    if (w) { if (!MultiByteToWideChar(CP_ACP, 0, s, -1, w, n)) w[0] = 0; }
    return w;
}
static SOCKADDR *sa4(BUMP *b, ULONG addr)
{
    struct sockaddr_in *s = (struct sockaddr_in *)take(b, sizeof(*s));
    if (s) { s->sin_family = AF_INET; s->sin_addr.s_addr = addr; }
    return (SOCKADDR *)s;
}

/* one pass: count (b->p NULL) or fill */
static ULONG build(BUMP *b, IP_ADAPTER_INFO *ai, FIXED_INFO *fi, ULONG flags)
{
    IP_ADAPTER_ADDRESSES *first = NULL, *prev = NULL; ULONG n = 0;
    for (; ai; ai = ai->Next) {
        IP_ADAPTER_ADDRESSES *a; IP_ADDR_STRING *ip; ULONG addr0 = a4(ai->IpAddressList.IpAddress.String);
        if (!addr0) continue;                                   /* no address (cable unplugged / DHCP pending) */
        a = (IP_ADAPTER_ADDRESSES *)take(b, sizeof(IP_ADAPTER_ADDRESSES));
        if (a) {
            char *nm; ULONG k;
            a->Length = sizeof(IP_ADAPTER_ADDRESSES); a->IfIndex = ai->Index;
            nm = (char *)take(b, lstrlenA(ai->AdapterName) + 1); if (nm) lstrcpyA(nm, ai->AdapterName);
            a->AdapterName = nm;
            for (k = 0; k < ai->AddressLength && k < MAX_ADAPTER_ADDRESS_LENGTH; k++) a->PhysicalAddress[k] = ai->Address[k];
            a->PhysicalAddressLength = ai->AddressLength > 8 ? 8 : ai->AddressLength;
            a->Flags = IP_ADAPTER_IPV4_ENABLED | (ai->DhcpEnabled ? IP_ADAPTER_DHCP_ENABLED : 0);
            a->Mtu = 1500;
            a->IfType = ai->Type == MIB_IF_TYPE_PPP ? IF_TYPE_PPP : ai->Type == MIB_IF_TYPE_LOOPBACK ? IF_TYPE_SOFTWARE_LOOPBACK : IF_TYPE_ETHERNET_CSMACD;
            a->OperStatus = IfOperStatusUp;
            a->TransmitLinkSpeed = a->ReceiveLinkSpeed = 100000000ULL;
            a->Ipv4Metric = 20;
            a->Luid.Info.NetLuidIndex = ai->Index; a->Luid.Info.IfType = a->IfType;
            a->ConnectionType = NET_IF_CONNECTION_DEDICATED;
            a->TunnelType = TUNNEL_TYPE_NONE;
            if (ai->DhcpEnabled) { ULONG d = a4(ai->DhcpServer.IpAddress.String); if (d) { a->Dhcpv4Server.lpSockaddr = sa4(b, d); a->Dhcpv4Server.iSockaddrLength = sizeof(struct sockaddr_in); } }
        }
        {   WCHAR *dsfx = (WCHAR *)take(b, sizeof(WCHAR)), *desc, *fr;
            desc = wdup(b, ai->Description);
            fr = wdup(b, ai->Description);
            if (a) { a->DnsSuffix = dsfx; a->Description = desc; a->FriendlyName = fr; } }
        if (!(flags & GAA_FLAG_SKIP_UNICAST)) {
            IP_ADAPTER_UNICAST_ADDRESS *pu = NULL;
            for (ip = &ai->IpAddressList; ip; ip = ip->Next) {
                ULONG ad = a4(ip->IpAddress.String); IP_ADAPTER_UNICAST_ADDRESS *u;
                if (!ad) continue;
                u = (IP_ADAPTER_UNICAST_ADDRESS *)take(b, sizeof(IP_ADAPTER_UNICAST_ADDRESS));
                {   SOCKADDR *s = sa4(b, ad);
                    if (u) {
                        u->Length = sizeof(*u); u->Flags = 0;
                        u->Address.lpSockaddr = s; u->Address.iSockaddrLength = sizeof(struct sockaddr_in);
                        u->PrefixOrigin = ai->DhcpEnabled ? IpPrefixOriginDhcp : IpPrefixOriginManual;
                        u->SuffixOrigin = ai->DhcpEnabled ? IpSuffixOriginDhcp : IpSuffixOriginManual;
                        u->DadState = IpDadStatePreferred;
                        u->ValidLifetime = u->PreferredLifetime = u->LeaseLifetime = 0xFFFFFFFFUL;
                        u->OnLinkPrefixLength = prefix_len(a4(ip->IpMask.String));
                        if (pu) pu->Next = u; else if (a) a->FirstUnicastAddress = u;
                        pu = u;
                    } }
            }
        }
        if (flags & GAA_FLAG_INCLUDE_GATEWAYS) {
            IP_ADAPTER_GATEWAY_ADDRESS_LH *pg = NULL;
            for (ip = &ai->GatewayList; ip; ip = ip->Next) {
                ULONG ad = a4(ip->IpAddress.String); IP_ADAPTER_GATEWAY_ADDRESS_LH *g;
                if (!ad) continue;
                g = (IP_ADAPTER_GATEWAY_ADDRESS_LH *)take(b, sizeof(*g));
                {   SOCKADDR *s = sa4(b, ad);
                    if (g) { g->Length = sizeof(*g); g->Address.lpSockaddr = s; g->Address.iSockaddrLength = sizeof(struct sockaddr_in);
                             if (pg) pg->Next = g; else if (a) a->FirstGatewayAddress = g; pg = g; } }
            }
        }
        if (!(flags & GAA_FLAG_SKIP_DNS_SERVER) && fi) {
            IP_ADAPTER_DNS_SERVER_ADDRESS *pd = NULL;
            for (ip = &fi->DnsServerList; ip; ip = ip->Next) {
                ULONG ad = a4(ip->IpAddress.String); IP_ADAPTER_DNS_SERVER_ADDRESS *d;
                if (!ad) continue;
                d = (IP_ADAPTER_DNS_SERVER_ADDRESS *)take(b, sizeof(*d));
                {   SOCKADDR *s = sa4(b, ad);
                    if (d) { d->Length = sizeof(*d); d->Address.lpSockaddr = s; d->Address.iSockaddrLength = sizeof(struct sockaddr_in);
                             if (pd) pd->Next = d; else if (a) a->FirstDnsServerAddress = d; pd = d; } }
            }
        }
        if (a) { if (prev) prev->Next = a; else first = a; prev = a; }
        n++;
    }
    (void)first;
    return n;
}

static ULONG get_info(IP_ADAPTER_INFO **ai, FIXED_INFO **fi)
{
    T_GAI gai = (T_GAI)(void *)kex_sysproc("IPHLPAPI.DLL", "GetAdaptersInfo");
    T_GNP gnp = (T_GNP)(void *)kex_sysproc("IPHLPAPI.DLL", "GetNetworkParams");
    ULONG sz = 0, r;
    *ai = NULL; *fi = NULL;
    if (!gai) return ERROR_NOT_SUPPORTED;
    r = gai(NULL, &sz);
    if (r != ERROR_BUFFER_OVERFLOW || !sz) return r == ERROR_SUCCESS ? ERROR_NO_DATA : r;
    if (!(*ai = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), 0, sz + 64))) return ERROR_NOT_ENOUGH_MEMORY;
    if ((r = gai(*ai, &sz)) != ERROR_SUCCESS) { HeapFree(GetProcessHeap(), 0, *ai); *ai = NULL; return r; }
    if (gnp) {
        ULONG fs = 0;
        if (gnp(NULL, &fs) == ERROR_BUFFER_OVERFLOW && fs && (*fi = (FIXED_INFO *)HeapAlloc(GetProcessHeap(), 0, fs + 64)) != NULL &&
            gnp(*fi, &fs) != ERROR_SUCCESS) { HeapFree(GetProcessHeap(), 0, *fi); *fi = NULL; }
    }
    return ERROR_SUCCESS;
}

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
ULONG KEXAPI kex_GetAdaptersAddresses(ULONG fam, ULONG flags, PVOID res, PVOID addrs, PULONG size)
{
    IP_ADAPTER_INFO *ai; FIXED_INFO *fi; BUMP b; ULONG r, n;
    (void)res;
    if (!size) return ERROR_INVALID_PARAMETER;
    if (fam != AF_UNSPEC && fam != AF_INET) return fam == AF_INET6 ? ERROR_NO_DATA : ERROR_INVALID_PARAMETER;
    if ((r = get_info(&ai, &fi)) != ERROR_SUCCESS) return r;
    b.p = NULL; b.used = 0; b.cap = 0;
    n = build(&b, ai, fi, flags);
    if (!n) r = ERROR_NO_DATA;
    else if (!addrs || *size < b.used) { *size = b.used; r = ERROR_BUFFER_OVERFLOW; }
    else {
        b.p = (BYTE *)addrs; b.cap = *size; b.used = 0;
        build(&b, ai, fi, flags);
        r = ERROR_SUCCESS;
    }
    {   static LONG k; if (InterlockedIncrement(&k) <= 3)
            kex_crashnote("GetAdaptersAddresses from Windows 98's GetAdaptersInfo (family, flags, adapters, result)", fam, flags, n, r); }
    if (ai) HeapFree(GetProcessHeap(), 0, ai);
    if (fi) HeapFree(GetProcessHeap(), 0, fi);
    return r;
}

/* the adapter's name for an index and back (names as GetAdaptersInfo has them) */
PCHAR KEXAPI kex_if_indextoname(ULONG idx, PCHAR name)
{
    IP_ADAPTER_INFO *ai, *p; FIXED_INFO *fi; PCHAR r = NULL;
    if (!name || get_info(&ai, &fi) != ERROR_SUCCESS) return NULL;
    for (p = ai; p; p = p->Next) if (p->Index == idx) { lstrcpynA(name, p->AdapterName, 256); r = name; break; }
    if (ai) HeapFree(GetProcessHeap(), 0, ai);
    if (fi) HeapFree(GetProcessHeap(), 0, fi);
    return r;
}
ULONG KEXAPI kex_if_nametoindex(PCSTR name)
{
    IP_ADAPTER_INFO *ai, *p; FIXED_INFO *fi; ULONG r = 0;
    if (!name || get_info(&ai, &fi) != ERROR_SUCCESS) return 0;
    for (p = ai; p; p = p->Next) if (!lstrcmpiA(p->AdapterName, name)) { r = p->Index; break; }
    if (ai) HeapFree(GetProcessHeap(), 0, ai);
    if (fi) HeapFree(GetProcessHeap(), 0, fi);
    return r;
}

/*
 * KEXALIAS.VXD - KernelEx-NG helper VxD (dynamically loaded): a second linear address for shared memory.
 *
 * Windows 98 maps a file-mapping object once, at one address in the shared arena; mapping it again in the same
 * process returns the same pointer. Windows NT gives every MapViewOfFile its own view. Chromium's Mojo/ipcz data
 * pipes map the same region twice in the creating process (consumer + producer, ipcz_driver/data_pipe.cc) and
 * base::SharedMemoryTracker keys mappings by address (shared_memory_tracker.cc:62 CHECKs). kexnt asks this VxD
 * for an ALIAS: new linear pages in the shared arena that point at the same physical pages, so writes through
 * one address are seen through the other at once (same RAM, x86 caches are physically tagged).
 *
 *   IOCTL 1  ALIAS    in: {source address (page aligned), byte count}  out: {alias address (64 KB aligned), reservation}
 *                     source pages are locked (resident, physical page fixed) for the alias' lifetime
 *   IOCTL 2  UNALIAS  in: {alias address, source address, byte count, reservation}
 *                     optional out (version 4): {pages written through the alias, of them clean in the source}
 *   IOCTL 3  VERSION  out: {version}
 *   IOCTL 4  PTES     in: {linear address, page count <= 64}  out: the page-table entries (read only; version 5:
 *                     kextest asks where the shared arena's big blocks live - RAM or a device such as video memory)
 *   IOCTL 5  VXDLIST  out: {count, then per VxD: DDB address, name[8], control procedure, init order} (version 6)
 *   IOCTL 6  FINDPTR  in: {range lo, range hi, scan start, scan end, RAM top}  out: {pages read, hits, then up to
 *                     64 pairs (address, value)} - DWORDs in [lo, hi) stored in present RAM pages of [start, end)
 *                     (system arena: tells WHICH driver keeps a pointer to a block; version 6, read only)
 *
 * Only documented VMM services (_LinPageLock, _CopyPageTable, _PageReserve, _PageCommitPhys, _PageDecommit,
 * _PageFree, _LinPageUnLock). Built with Open Watcom like JHRobotics' vmdisp9x VxDs (MIT), whose vmm.h is used.
 */
#include "winhack.h"
#include "vmm.h"

#define KEXALIAS_VERSION 6
#define KEXALIAS_MAX_PAGES 65536         /* 256 MB per alias (Chromium mapped 24 MB, build 19) */

void KEXALIAS_control(void);

/* must be the first data of the image (VxD loader / wlink) */
DDB VXD_DDB = {
	0,                              /* next */
	DDK_VERSION,
	0,                              /* Undefined_Device_ID: dynamic, no services exported */
	1, 0,                           /* version */
	0,                              /* flags */
	"KEXALIAS",
	Undefined_Init_Order,
	(DWORD)KEXALIAS_control,
	0, 0,                           /* V86 / PM API */
	0, 0, 0,                        /* V86/PM API CS:IP, reference data */
	0, 0,                           /* service table, count */
	0,                              /* Win32 service table */
	'Prev',
	sizeof(DDB),
	'Rsv1', 'Rsv2', 'Rsv3',
};

ULONG __declspec(naked) __cdecl k_CopyPageTable(ULONG LinPgNum, ULONG nPages, DWORD *PageBuf, ULONG flags)
{
	VMMJmp(_CopyPageTable);
}
ULONG __declspec(naked) __cdecl k_LinPageLock(ULONG page, ULONG npages, ULONG flags)
{
	VMMJmp(_LinPageLock);
}
ULONG __declspec(naked) __cdecl k_LinPageUnLock(ULONG page, ULONG npages, ULONG flags)
{
	VMMJmp(_LinPageUnLock);
}
DWORD __declspec(naked) __cdecl k_PageReserve(ULONG page, ULONG npages, ULONG flags)
{
	VMMJmp(_PageReserve);
}
DWORD __declspec(naked) __cdecl k_PageCommitPhys(ULONG page, ULONG npages, ULONG physpg, ULONG flags)
{
	VMMJmp(_PageCommitPhys);
}
DWORD __declspec(naked) __cdecl k_PageDecommit(ULONG page, ULONG npages, ULONG flags)
{
	VMMJmp(_PageDecommit);
}
ULONG __declspec(naked) __cdecl k_PageFree(PVOID hMem, DWORD flags)
{
	VMMJmp(_PageFree);
}

/* Version 2: the alias starts on a 64 KB boundary. Chromium assumes NT's allocation granularity for views and
 * unmaps AlignDown(view, 64 KB) (base/memory/shared_memory_mapping.cc), so every view kexnt hands out must be
 * 64 KB aligned. 15 extra pages are reserved in front and stay unused. *reserved = what _PageFree needs. */
static DWORD do_alias(DWORD src, DWORD bytes, DWORD *reserved)
{
	DWORD n, first, base, al, i, pte;
	if (!src || (src & 0xFFF) || !bytes) return 0;
	n = (bytes + 0xFFF) >> 12;
	if (n > KEXALIAS_MAX_PAGES) return 0;
	first = src >> 12;
	if (!k_LinPageLock(first, n, 0)) return 0;                       /* resident + physical pages fixed */
	/* Version 3: whole 64 KB windows. The alias may be the only thing in its 64 KB window(s): kexnt hands out other
	 * views at their real Win98 addresses and resolves an unmap of AlignDown(view, 64 KB) to them - a small alias at
	 * W and a real view at W+5000h made that address ambiguous (kextest build 33). So reserve the alias rounded up
	 * to 16 pages, plus the 15 pages of slack for the 64 KB start. */
	base = k_PageReserve(PR_SHARED, ((n + 15) & ~15UL) + 15, PR_FIXED);
	if (base == 0 || base == 0xFFFFFFFF) { k_LinPageUnLock(first, n, 0); return 0; }
	al = (base + 0xFFFF) & ~0xFFFFUL;
	for (i = 0; i < n; i++) {
		pte = 0;
		k_CopyPageTable(first + i, 1, &pte, 0);
		if (!(pte & 1) ||                                            /* not present: should not happen while locked */
		    !k_PageCommitPhys((al >> 12) + i, 1, pte >> 12, PC_USER | PC_WRITEABLE)) {
			if (i) k_PageDecommit(al >> 12, i, 0);
			k_PageFree((PVOID)base, 0);
			k_LinPageUnLock(first, n, 0);
			return 0;
		}
	}
	*reserved = base;
	return al;
}

/* Version 4 (build 101): the DIRTY bit. A write through the alias sets the dirty bit (PTE bit 6) in the ALIAS's
 * page-table entry only; the section's own entry - the one Windows 98's pager looks at - stays "clean". While the
 * alias lives the pages are locked, so nothing happens. Once it is gone they are unlocked, and under memory pressure
 * the pager may drop such a "clean" page without saving it: the next reader (Chrome's renderer, reading a Mojo data
 * pipe the browser filled through its alias) gets a fresh ZERO page. Build 100 caught exactly that: every broken
 * Discord script reached V8 as zeros of the right length. Before the alias goes, every page written through it is
 * written once more through the section's own address (lock or [p],0 - the value stays, the dirty bit is set). */
static void __declspec(naked) touch_dirty(DWORD *p)
{
	_asm {
		mov eax, [esp+4]
		lock or dword ptr [eax], 0
		ret
	}
}
static DWORD g_last_dirty, g_last_fixed;
static DWORD do_unalias(DWORD alias, DWORD src, DWORD bytes, DWORD reserved)
{
	DWORD n, i, pa, ps;
	if (!alias || (alias & 0xFFF) || !src || (src & 0xFFF) || !bytes || !reserved) return 0;
	n = (bytes + 0xFFF) >> 12;
	if (n > KEXALIAS_MAX_PAGES) return 0;
	g_last_dirty = 0; g_last_fixed = 0;
	for (i = 0; i < n; i++) {
		pa = 0; ps = 0;
		k_CopyPageTable((alias >> 12) + i, 1, &pa, 0);
		if ((pa & 0x41) != 0x41) continue;                           /* present and written through the alias? */
		g_last_dirty++;
		k_CopyPageTable((src >> 12) + i, 1, &ps, 0);
		if ((ps & 0x41) == 0x01) {                                   /* present in the section, but "clean" there */
			touch_dirty((DWORD *)(src + (i << 12)));
			g_last_fixed++;
		}
	}
	k_PageDecommit(alias >> 12, n, 0);
	k_PageFree((PVOID)reserved, 0);
	k_LinPageUnLock(src >> 12, n, 0);
	return 1;
}

/* VMM's DDB (Get_DDB by device id 1); the loaded VxDs follow through DDB_Next */
static DWORD vmm_ddb(void)
{
	DWORD r = 0;
	_asm push edi
	_asm push ebx
	_asm mov eax, 1
	_asm xor edi, edi
	VMMCall(Get_DDB)
	_asm mov r, ecx
	_asm pop ebx
	_asm pop edi
	return r;
}

static DWORD vxd_list(DWORD *out, DWORD cb)
{
	DWORD d = vmm_ddb(), n = 0, max = (cb - 4) / 24, *o = out + 1;
	BYTE *b;
	while (d && n < max && n < 512) {
		b = (BYTE *)d;
		o[0] = d;
		o[1] = *(DWORD *)(b + 12); o[2] = *(DWORD *)(b + 16);  /* name */
		o[3] = *(DWORD *)(b + 24);                               /* control proc */
		o[4] = *(DWORD *)(b + 20);                               /* init order */
		o[5] = *(WORD *)(b + 6);                                 /* device id */
		o += 6; n++;
		d = *(DWORD *)b;
	}
	out[0] = n;
	return 4 + n * 24;
}

static DWORD find_ptr(DWORD *in, DWORD *out, DWORD cb)
{
	DWORD lo = in[0], hi = in[1], lin = in[2] & ~0xFFFUL, end = in[3], ramtop = in[4];
	DWORD pages = 0, hits = 0, max = (cb - 8) / 8, pte, i, *p;
	while (lin < end) {
		if (!(lin >= (lo & ~0xFFFUL) && lin < hi)) {
			pte = 0;
			k_CopyPageTable(lin >> 12, 1, &pte, 0);
			if ((pte & 1) && (pte & 0xFFFFF000UL) < ramtop &&
			    !((pte & 0xFFFFF000UL) >= 0xA0000UL && (pte & 0xFFFFF000UL) < 0x100000UL)) {
				pages++;
				p = (DWORD *)lin;
				for (i = 0; i < 1024; i++)
					if (p[i] - lo < hi - lo) {
						if (hits < max) { out[2 + hits * 2] = lin + i * 4; out[3 + hits * 2] = p[i]; }
						hits++;
					}
			}
		}
		if (lin + 0x1000UL < lin) break;
		lin += 0x1000UL;
	}
	out[0] = pages; out[1] = hits;
	return 8 + (hits < max ? hits : max) * 8;
}

DWORD __stdcall KEXALIAS_ioctl(DWORD vm, struct DIOCParams *p)
{
	DWORD *in = (DWORD *)p->lpInBuffer, *out = (DWORD *)p->lpOutBuffer;
	switch (p->dwIoControlCode) {
	case DIOC_OPEN:
	case DIOC_CLOSEHANDLE:
		return 0;
	case 1:
		if (!in || p->cbInBuffer < 8 || !out || p->cbOutBuffer < 8) return 87;
		out[1] = 0;
		out[0] = do_alias(in[0], in[1], &out[1]);
		if (p->lpcbBytesReturned) *(DWORD *)p->lpcbBytesReturned = 8;
		return out[0] ? 0 : 8;                                       /* ERROR_NOT_ENOUGH_MEMORY */
	case 2:
		if (!in || p->cbInBuffer < 16) return 87;
		if (!do_unalias(in[0], in[1], in[2], in[3])) return 87;
		if (out && p->cbOutBuffer >= 8) {
			out[0] = g_last_dirty; out[1] = g_last_fixed;
			if (p->lpcbBytesReturned) *(DWORD *)p->lpcbBytesReturned = 8;
		}
		return 0;
	case 4:
		if (!in || p->cbInBuffer < 8 || !out || in[1] == 0 || in[1] > 64 || p->cbOutBuffer < in[1] * 4) return 87;
		if (!k_CopyPageTable(in[0] >> 12, in[1], out, 0)) return 87;
		if (p->lpcbBytesReturned) *(DWORD *)p->lpcbBytesReturned = in[1] * 4;
		return 0;
	case 5:
		if (!out || p->cbOutBuffer < 28) return 87;
		{ DWORD n = vxd_list(out, p->cbOutBuffer); if (p->lpcbBytesReturned) *(DWORD *)p->lpcbBytesReturned = n; }
		return 0;
	case 6:
		if (!in || p->cbInBuffer < 20 || !out || p->cbOutBuffer < 16 || in[1] <= in[0] || in[3] <= in[2]) return 87;
		{ DWORD n = find_ptr(in, out, p->cbOutBuffer); if (p->lpcbBytesReturned) *(DWORD *)p->lpcbBytesReturned = n; }
		return 0;
	case 3:
		if (!out || p->cbOutBuffer < 4) return 87;
		out[0] = KEXALIAS_VERSION;
		if (p->lpcbBytesReturned) *(DWORD *)p->lpcbBytesReturned = 4;
		return 0;
	}
	return 50;                                                       /* ERROR_NOT_SUPPORTED */
}

/* control procedure: EAX = message; carry clear = success */
void __declspec(naked) KEXALIAS_control(void)
{
	_asm {
		cmp eax, W32_DEVICEIOCONTROL
		jnz not_ioctl
		push esi
		push ebx
		call KEXALIAS_ioctl
		clc
		ret
	not_ioctl:
		clc
		ret
	}
}

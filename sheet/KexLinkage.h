/*
 *  KernelEx
 *  Copyright (C) 2009, Xeno86
 *
 *  This file is part of KernelEx source code.
 *
 *  KernelEx is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; version 2 of the License.
 *
 *  KernelEx is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __KEXLINKAGE_H
#define __KEXLINKAGE_H

#include <windows.h>
#ifdef __GNUC__
inline void* operator new(size_t, void* p) noexcept { return p; }   /* placement new without <new> */
#endif

#include "sstring.hpp"
#ifdef __GNUC__
#include "kexcore_min.h"
#else
#include "kexcoresdk.h"
#endif

/* KernelEx-NG: a minimal growable array instead of std::vector, so sheet.dll builds with MinGW without a C++
 * runtime (only push_back / size / empty / operator[] are used). */
template <class T> class kvec
{
public:
	kvec() : p(0), n(0), cap(0) {}
	~kvec() { for (int i = 0; i < n; i++) p[i].~T(); if (p) HeapFree(GetProcessHeap(), 0, p); }
	void push_back(const T& v)
	{
		if (n == cap)
		{
			int nc = cap ? cap * 2 : 16;
			T* q = (T*) HeapAlloc(GetProcessHeap(), 0, nc * sizeof(T));
			if (!q) return;
			for (int i = 0; i < n; i++) { new (&q[i]) T(p[i]); p[i].~T(); }
			if (p) HeapFree(GetProcessHeap(), 0, p);
			p = q; cap = nc;
		}
		new (&p[n]) T(v); n++;
	}
	int size() const { return n; }
	bool empty() const { return n == 0; }
	T& operator[](int i) { return p[i]; }
	const T& operator[](int i) const { return p[i]; }
private:
	T* p; int n, cap;
};

class KexLinkage  
{
	typedef void (*kexGetModuleSettings_t)(const char* module, 
			char* conf_name, DWORD* mod_flags);
	typedef void (*kexSetModuleSettings_t)(const char* module, 
			const char* conf_name, DWORD mod_flags);
	typedef void (*kexResetModuleSettings_t)(const char* module);
	typedef unsigned long (*kexGetKEXVersion_t)(void);
	typedef DWORD (*kexGetCoreCaps_t)(void);

public:

	struct conf
	{
		conf(const char* n, const char* d) : name(n), desc(d) {}
		sstring name;
		sstring desc;
	};

	~KexLinkage();
	bool IsReady();
	
	static KexLinkage instance;
	kvec<conf> confs;
	int default_index;
	bool disable_extensions;
	kexGetModuleSettings_t m_kexGetModuleSettings;
	kexSetModuleSettings_t m_kexSetModuleSettings;
	kexResetModuleSettings_t m_kexResetModuleSettings;
	kexGetKEXVersion_t m_kexGetKEXVersion;
	kexGetCoreCaps_t m_kexGetCoreCaps;

protected:
	KexLinkage();
	bool Prepare();
	
	HMODULE hKernelEx;
	bool m_ready;
};

#endif

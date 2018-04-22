// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;;
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Cxbx->Win32->XBNetwork.cpp
// *
// *  This file is part of the Cxbx project.
// *
// *  Cxbx and Cxbe are free software; you can redistribute them
// *  and/or modify them under the terms of the GNU General Public
// *  License as published by the Free Software Foundation; either
// *  version 2 of the license, or (at your option) any later version.
// *
// *  This program is distributed in the hope that it will be useful,
// *  but WITHOUT ANY WARRANTY; without even the implied warranty of
// *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// *  GNU General Public License for more details.
// *
// *  You should have recieved a copy of the GNU General Public License
// *  along with this program; see the file COPYING.
// *  If not, write to the Free Software Foundation, Inc.,
// *  59 Temple Place - Suite 330, Bostom, MA 02111-1307, USA.
// *
// *  (c) 2018 Luke Usher
// *
// *  All rights reserved
// *
// ******************************************************************
#include "XBNetwork.h"

#include <cstdio>

void XBNetwork::Load(const char *szRegistryKey)
{
    DWORD   dwDisposition, dwType, dwSize;
    HKEY    hKey;

    if(RegCreateKeyEx(HKEY_CURRENT_USER, szRegistryKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        dwType = REG_SZ; dwSize = MAX_PATH;
        RegQueryValueEx(hKey, "NetworkAdapterName", NULL, &dwType, (PBYTE)m_NetworkAdapterName, &dwSize);
        RegCloseKey(hKey);
    }
}

void XBNetwork::Save(const char *szRegistryKey)
{
	if (g_SaveOnExit) {
		DWORD   dwDisposition, dwType, dwSize;
		HKEY    hKey;

		if (RegCreateKeyEx(HKEY_CURRENT_USER, szRegistryKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
			dwType = REG_SZ; dwSize = MAX_PATH;
			RegSetValueEx(hKey, "NetworkAdapterName", 0, dwType, (PBYTE)m_NetworkAdapterName, dwSize);
			RegCloseKey(hKey);
		}
	}
}

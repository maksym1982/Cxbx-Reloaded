// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;;
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Cxbx->Win32->Cxbx->XBNetwork.h
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
#ifndef XBNETWORK_H
#define XBNETWORK_H

#include "Cxbx.h"
#include "Common/Error.h"
#include "Mutex.h"

// ******************************************************************
// * class: XBNetwork
// ******************************************************************
class XBNetwork : public Error
{
    public:
        void Load(const char *szRegistryKey);
        void Save(const char *szRegistryKey);

		void  SetNetworkAdpater(std::string adapter) { adapter.copy(m_NetworkAdapterName, MAX_PATH, 0);  };
        std::string GetNetworkAdapter() { return m_NetworkAdapterName; }
    private:
		char m_NetworkAdapterName[MAX_PATH];
};

#endif

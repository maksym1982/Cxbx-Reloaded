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

#include "AC97Device.h"
#include "devices\Xbox.h"

AC97Device::AC97Device(Xbox* pXbox)
{
	m_pXbox = pXbox;
}

void AC97Device::Init()
{
	PCIBarRegister r;
	r.IO.address = 0xD000;
	r.Raw.type = PCI_BAR_TYPE_IO;
	RegisterBAR(0, 256, r.value);

	r.IO.address = 0xD200;
	r.Raw.type = PCI_BAR_TYPE_IO;
	RegisterBAR(1, 128, r.value);

	r.IO.address = 0xFEC00000 >> 4;
	r.Raw.type = PCI_BAR_TYPE_MEMORY;
	RegisterBAR(2, 4096, r.value);

//	m_DeviceId = ?;
	m_VendorId = PCI_VENDOR_ID_NVIDIA;
}

void AC97Device::Reset()
{
}

uint32_t AC97Device::IORead(int barIndex, uint32_t port, unsigned size)
{
	printf("AC97: IORead\n");
	return 0;
}

void AC97Device::IOWrite(int barIndex, uint32_t port, uint32_t value, unsigned size)
{
	printf("AC97: IOWrite\n");
}

uint32_t AC97Device::MMIORead(int barIndex, uint32_t addr, unsigned size)
{
	printf("AC97: MMIORead\n");
	return 0;
}

void AC97Device::MMIOWrite(int barIndex, uint32_t addr, uint32_t value, unsigned size)
{
	printf("AC97: MMIOWrite\n");
}

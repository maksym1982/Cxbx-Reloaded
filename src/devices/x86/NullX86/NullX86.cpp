// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;;
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Hardware->X86->NullX86/NullX86.cpp
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
// *  (c) 2018 Luke Usher <luke.usher@outlook.com>
// *  All rights reserved
// *
// ******************************************************************

#include "NullX86.h"
#include "devices\Xbox.h"

bool NullX86::IsSupported()
{
	return false;
}

bool NullX86::Init(Xbox* xbox)
{
	m_pXbox = xbox;
	return false;
}

void NullX86::Reset()
{
}

void NullX86::Shutdown()
{
}

bool NullX86::ReadRegister(const X86Reg reg, uint32_t & value)
{
	return false;
}

bool NullX86::WriteRegister(const X86Reg reg, const uint32_t value)
{
	return false;
}

X86ExecutionModes NullX86::GetSupportedExecutionModes()
{
	return X86ExecutionModes();
}

bool NullX86::Step()
{
	return false;
}

bool NullX86::ExecuteBlock()
{
	return false;
}

bool NullX86::Execute()
{
	return false;
}

bool NullX86::Interrupt(uint8_t vector)
{
	return false;
}

bool NullX86::GetPhysicalAddress(const uint32_t virtaddr, uint32_t & physaddr)
{
	return false;
}

bool NullX86::ReadVirtualMemory(const uint32_t addr, uint32_t & value, const size_t size)
{
	return false;
}

bool NullX86::WriteVirtualMemory(const uint32_t addr, const uint32_t value, const size_t size)
{
	return false;
}


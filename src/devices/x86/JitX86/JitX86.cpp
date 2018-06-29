// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;;
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Hardware->X86->JitX86/JitX86.cpp
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

#include "JitX86.h"
#include "devices\Xbox.h"

bool JitX86::IsSupported()
{
	// JitX86 is only supported on X86 platforms, but in that case we 
	// just won't compile it into the executable, no need to check that here
	return true;
}

bool JitX86::Init(Xbox* xbox)
{
	m_pXbox = xbox;
	return true;
}

void JitX86::Reset()
{
}

void JitX86::Shutdown()
{
}

bool JitX86::ReadRegister(const X86Reg reg, uint32_t & value)
{
	return false;
}

bool JitX86::WriteRegister(const X86Reg reg, const uint32_t value)
{
	return false;
}

X86ExecutionModes JitX86::GetSupportedExecutionModes()
{
	return X86ExecutionModes();
}

bool JitX86::Step()
{
	return false;
}

bool JitX86::ExecuteBlock()
{
	return false;
}

bool JitX86::Execute()
{
	return false;
}

bool JitX86::Interrupt(uint8_t vector)
{
	return false;
}

bool JitX86::GetPhysicalAddress(const uint32_t virtaddr, uint32_t & physaddr)
{
	return false;
}

bool JitX86::ReadVirtualMemory(const uint32_t addr, uint32_t & value, const size_t size)
{
	return false;
}

bool JitX86::WriteVirtualMemory(const uint32_t addr, const uint32_t value, const size_t size)
{
	return false;
}


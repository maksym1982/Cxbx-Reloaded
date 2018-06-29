// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;;
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Hardware->X86->NullX86/NullX86.h
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

#ifndef NULLX86_H
#define NULLX86_H

#include "devices\x86\IX86CPU.h"
class Xbox;

class NullX86 : public IX86CPU
{
public:
	bool IsSupported();

	// State Control
	bool Init(Xbox* xbox);
	void Reset();
	void Shutdown();

	// Register Get/Set
	bool ReadRegister(const X86Reg reg, uint32_t& value);
	bool WriteRegister(const X86Reg reg, const uint32_t value);
	 
	// Execution
	X86ExecutionModes GetSupportedExecutionModes();
	bool Step();					// Step for a single instruction (optional)
	bool ExecuteBlock();			// Execute a single code block (usually, this means until a branch is hit)
	bool Execute();					// Execute indefinitely (Until an interrupt is encountered)
	bool Interrupt(uint8_t vector); // Trigger an interrupt

	// Memory Access (Virtual Address Space: Parses page tables)
	bool GetPhysicalAddress(const uint32_t virtaddr, uint32_t& physaddr); // Returns the Physical Address for a given virtual address
	bool ReadVirtualMemory(const uint32_t addr, uint32_t& value, const size_t size);
	bool WriteVirtualMemory(const uint32_t addr, const uint32_t value, const size_t size);
private:
	Xbox* m_pXbox = nullptr;
}; 

#endif
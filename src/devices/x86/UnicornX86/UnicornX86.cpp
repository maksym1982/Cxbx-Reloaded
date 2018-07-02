// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;;
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Hardware->X86->UnicornX86/UnicornX86.cpp
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

// Prevent a compilation error caused by Unicorn including winsock2 after
// Windows.h is included by Cxbx-R
#define _WINSOCKAPI_ 

#include <mutex>

#include "UnicornX86.h"
#include "devices\Xbox.h"

// Private variables are local instead of class scope
// This is to avoid headers (like unicorn) accidentally becoming global
// Namespacing this causes weird compiler errors
#include "unicorn\include\unicorn\\unicorn.h"
uc_engine* uc = nullptr;

const uint32_t MMIO_BASE = 0xFD000000;

uc_hook uc_hook_ioread;
uc_hook uc_hook_iowrite;
uc_hook uc_hook_get_interrupt;

constexpr long cyclesPerFrame = (733333333) / 60;

uint64_t mmio_read_cb(struct uc_struct* uc, void* userdata, uint64_t addr, unsigned size)
{
	Xbox* pXbox = (Xbox*)userdata;
	uint32_t result = 0;
	pXbox->ReadPhysicalMemory(addr + MMIO_BASE, result, size);
	return result;
}

void mmio_write_cb(struct uc_struct* uc, void* userdata, uint64_t addr, uint64_t data, unsigned size)
{
	Xbox* pXbox = (Xbox*)userdata;
	pXbox->WritePhysicalMemory(addr + MMIO_BASE, (uint32_t)data, size);
}

uint32_t io_read_cb(uc_engine *uc, uint32_t port, int size, Xbox* pXbox)
{
	uint32_t value;
	pXbox->IORead(port, value, size);
	return value;
}

int uc_get_interrupt_cb(uc_engine* uc, void* userdata)
{
	Xbox* pXbox = (Xbox*)userdata;
	return pXbox->GetPIC()->GetCurrentIRQ();
}

void io_write_cb(uc_engine *uc, uint32_t port, int size, uint32_t value, Xbox* pXbox)
{
	pXbox->IOWrite(port, value, size);
}

bool UnicornX86::IsSupported()
{
	// Unicorn is always supported by the host
	return true;
}

bool UnicornX86::Init(Xbox* xbox)
{
	m_pXbox = xbox;

	auto err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err) {
		return false;
	}

	err = uc_mem_map_ptr(uc, 0, m_pXbox->GetPhysicalMemorySize(), UC_PROT_ALL, m_pXbox->GetPhysicalMemoryPtr(0));
	if (err) {
		return false;
	}

	err = uc_mem_map_ptr(uc, 0xFF000000, 0x1000000, UC_PROT_ALL, m_pXbox->GetPhysicalMemoryPtr(0xFF000000));
	if (err) {
		return false;
	}

	err = uc_mmio_map(uc, MMIO_BASE, 0x2000000, mmio_read_cb, mmio_write_cb, xbox);
	if (err) {
		return false;
	}

	err = uc_hook_add(uc, &uc_hook_ioread, UC_HOOK_INSN, io_read_cb, xbox, 1, 0, UC_X86_INS_IN);

	if (err) {
		return false;
	}

	err = uc_hook_add(uc, &uc_hook_iowrite, UC_HOOK_INSN, io_write_cb, xbox, 1, 0, UC_X86_INS_OUT);
	if (err) {
		return false;
	}

	err = uc_hook_add(uc, &uc_hook_get_interrupt, UC_HOOK_GET_INTERRUPT, uc_get_interrupt_cb, xbox, 1, 0);

	return true;
}

void UnicornX86::Reset()
{
	
}

void UnicornX86::Shutdown()
{
	if (uc != nullptr) {
		uc_close(uc);
	}
}

bool UnicornX86::ReadRegister(const X86Reg reg, uint32_t& value)
{
	// Thanks to a design quirk, Cxbx-R and Unicorn Regs map 1:1
	auto err = uc_reg_read(uc, reg, &value);
	if (err) {
		return false;
	}

	return true;
}

bool UnicornX86::WriteRegister(const X86Reg reg, const uint32_t value)
{
	// Thanks to a design quirk, Cxbx-R and Unicorn Regs map 1:1
	uc_err error = UC_ERR_OK;

	switch (reg) {
		case X86_REG_GDTR:
		case X86_REG_IDTR:
			// Value points to a GDTR/IDTR entry in guest memory
			// Unicorn requires it presented as uc_x86_mmr
			uc_x86_mmr mmr;
			uc_mem_read(uc, value, &mmr.limit, sizeof(uint16_t));
			uc_mem_read(uc, value + sizeof(uint16_t), &mmr.base, sizeof(uint32_t));

			error = uc_reg_write(uc, reg, &mmr);
		break;
	default:
		uc_reg_write(uc, reg, &value);
		break;
	}

	if (error) {
		return false;
	}

	return true;
}

X86ExecutionModes UnicornX86::GetSupportedExecutionModes()
{
	return X86ExecutionModes();
}

bool UnicornX86::Step()
{
	return false;
}

bool UnicornX86::ExecuteBlock()
{
	return false;
}

bool UnicornX86::Execute()
{
	uint32_t eip;
	uc_reg_read(uc, UC_X86_REG_EIP, &eip);
	auto err = uc_emu_start(uc, eip, 0, 0, 0);
	uc_reg_read(uc, UC_X86_REG_EIP, &eip);

	if (err != UC_ERR_OK) {
		printf("Error %d", err);
		getchar();
	}
	
	return true;
}

bool UnicornX86::Interrupt()
{
	// Tell Unicorn there is a pending interrupt
	// Interrupt must be read from the PIC
	uc_emu_interrupt(uc);
	return true;
}

bool UnicornX86::GetPhysicalAddress(const uint32_t virtaddr, uint32_t & physaddr)
{
	return false;
}

bool UnicornX86::ReadVirtualMemory(const uint32_t addr, uint32_t & value, const size_t size)
{
	return false;
}

bool UnicornX86::WriteVirtualMemory(const uint32_t addr, const uint32_t value, const size_t size)
{
	return false;
}


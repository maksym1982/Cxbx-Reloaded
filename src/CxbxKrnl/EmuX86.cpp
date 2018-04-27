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
// *   Cxbx->Win32->CxbxKrnl->EmuX86.cpp
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
// *  (c) 2002-2003 Aaron Robinson <caustik@caustik.com>
// *  (c) 2016 Luke Usher <luke.usher@outlook.com>
// *  All rights reserved
// *
// ******************************************************************
#define _XBOXKRNL_DEFEXTRN_

#define LOG_PREFIX "X86 " // Intentional extra space to align on 4 characters
#include <unicorn\unicorn.h>

#include "CxbxKrnl.h"
#include "Emu.h" // For EmuWarning
#include "EmuX86.h"
#include "HLEIntercept.h" // for bLLE_GPU

#include <assert.h>
#include <unordered_map>
#include "devices\Xbox.h" // For g_PCIBus
#include "ld32.h"

extern uint32_t GetAPUTime();
std::unordered_map<DWORD, uc_engine*> g_UnicornHandles;
uc_engine* uc;
void* xbeMirror = nullptr;

//
// Read & write handlers handlers for I/O
//

static int field_pin = 0;

uint32_t EmuX86_IORead(xbaddr addr, int size)
{
	switch (addr) {
	case 0x8008: { // TODO : Move 0x8008 TIMER to a device
		if (size == sizeof(uint32_t)) {
			// HACK: This is very wrong.
			// This timer should count at a specific frequency (3579.545 ticks per ms)
			// But this is enough to keep NXDK from hanging for now.
			LARGE_INTEGER performanceCount;
			QueryPerformanceCounter(&performanceCount);
			return static_cast<uint32_t>(performanceCount.QuadPart);
		}
		break;
	}
	case 0x80C0: { // TODO : Move 0x80C0 TV encoder to a device
		if (size == sizeof(uint8_t)) {
			// field pin from tv encoder?
			field_pin = (field_pin + 1) & 1;
			return field_pin << 5;
		}
		break;
	}
	}

	// Pass the IO Read to the PCI Bus, this will handle devices with BARs set to IO addresses
	uint32_t value = 0;
	if (g_PCIBus->IORead(addr, &value, size)) {
		return value;
	}

	EmuWarning("EmuX86_IORead(0x%08X, %d) [Unhandled]", addr, size);
	return 0;
}

void EmuX86_IOWrite(xbaddr addr, uint32_t value, int size)
{
	// Pass the IO Write to the PCI Bus, this will handle devices with BARs set to IO addresses
	if (g_PCIBus->IOWrite(addr, value, size)) {
		return;
	}

	EmuWarning("EmuX86_IOWrite(0x%08X, 0x%04X, %d) [Unhandled]", addr, value, size);
}

//
// Read & write handlers for pass-through access to (host committed, virtual) xbox memory
//
// Only allowed to be called outside our EmuException exception handler,
// to prevent recursive exceptions when accessing unallocated memory.
//

uint32_t EmuX86_Mem_Read(xbaddr addr, int size)
{
	switch (size) {
	case sizeof(uint32_t) :
		return *(uint32_t*)addr;
	case sizeof(uint16_t) :
		return *(uint16_t*)addr;
	case sizeof(uint8_t) :
		return *(uint8_t*)addr;
	default:
		// UNREACHABLE(size);
		return 0;
	}
}

void EmuX86_Mem_Write(xbaddr addr, uint32_t value, int size)
{
	switch (size) {
	case sizeof(uint32_t) :
		*(uint32_t*)addr = (uint32_t)value;
		break;
	case sizeof(uint16_t) :
		*(uint16_t*)addr = (uint16_t)value;
		break;
	case sizeof(uint8_t) :
		*(uint8_t*)addr = (uint8_t)value;
		break;
	default:
		// UNREACHABLE(size);
		return;
	}
}

uint32_t EmuFlash_Read32(xbaddr addr) // TODO : Move to EmuFlash.cpp
{
	uint32_t r;

	switch (addr) {
	case 0x78: // ROM_VERSION
		r = 0x90; // Luke's hardware revision 1.6 Xbox returns this (also since XboxKrnlVersion is set to 5838)
		break;
	default:
		EmuWarning("Read32 FLASH_ROM (0x%.8X) [Unknown address]", addr);
		return -1;
	}

	DbgPrintf("X86 : Read32 FLASH_ROM (0x%.8X) = 0x%.8X [HANDLED]\n", addr, r);
	return r;
}

//
// Read & write handlers for memory-mapped hardware devices
//

uint32_t EmuX86_Read(xbaddr addr, int size)
{
	if ((addr & (size - 1)) != 0) {
		EmuWarning("EmuX86_Read(0x%08X, %d) [Unaligned unimplemented]", addr, size);
		// LOG_UNIMPLEMENTED();
		return 0;
	}

	uint32_t value;

	if (addr >= XBOX_FLASH_ROM_BASE) { // 0xFFF00000 - 0xFFFFFFF
		value = EmuFlash_Read32(addr - XBOX_FLASH_ROM_BASE); // TODO : Make flash access size-aware
	} else if(addr == 0xFE80200C) {
		// TODO: Remove this once we have an LLE APU Device
		return GetAPUTime();
	} else {
		// Pass the Read to the PCI Bus, this will handle devices with BARs set to MMIO addresses
		if (g_PCIBus->MMIORead(addr, &value, size)) {
			return value;
		}

		if (g_bEmuException) {
			EmuWarning("EmuX86_Read(0x%08X, %d) [Unknown address]", addr, size);
			value = 0;
		} else {
			// Outside EmuException, pass the memory-access through to normal memory :
			value = EmuX86_Mem_Read(addr, size);
		}

		DbgPrintf("X86 : Read(0x%08X, %d) = 0x%08X\n", addr, size, value);
	}

	return value;
}

void EmuX86_Write(xbaddr addr, uint32_t value, int size)
{
	if ((addr & (size - 1)) != 0) {
		EmuWarning("EmuX86_Write(0x%08X, 0x%08X, %d) [Unaligned unimplemented]", addr, value, size);
		// LOG_UNIMPLEMENTED();
		return;
	}

	if (addr >= XBOX_FLASH_ROM_BASE) { // 0xFFF00000 - 0xFFFFFFF
		EmuWarning("EmuX86_Write(0x%08X, 0x%08X) [FLASH_ROM]", addr, value);
		return;
	}

	// Pass the Write to the PCI Bus, this will handle devices with BARs set to MMIO addresses
	if (g_PCIBus->MMIOWrite(addr, value, size)) {
		return;
	}

	if (g_bEmuException) {
		EmuWarning("EmuX86_Write(0x%08X, 0x%08X) [Unknown address]", addr, value);
		return;
	}

	// Outside EmuException, pass the memory-access through to normal memory :
	DbgPrintf("X86 : Write(0x%.8X, 0x%.8X, %d)\n", addr, value, size);
	EmuX86_Mem_Write(addr, value, size);
}

// Unicorn MMIO->EmuX86 Wrappers
static uint64_t read_cb(struct uc_struct* uc, void *opaque, uint64_t addr, unsigned size) 
{
	return EmuX86_Read(addr + 0xFD000000, size);
}

static void write_cb(struct uc_struct* uc, void *opaque, uint64_t addr, uint64_t data, unsigned size)
{
	EmuX86_Write(addr + 0xFD000000, (uint32_t)data, size);
}

// Unicorn IO->EmuX86 Wrappers
static uint32_t hook_in_cb(uc_engine *uc, uint32_t port, int size, void *user_data)
{
	return EmuX86_IORead(port, size);
}

static void hook_out_cb(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
	EmuX86_IOWrite(port, value, size);
}

static void hook_unmapped_cb(uc_engine *uc, uc_mem_type type, uint64_t address, uint32_t size, int64_t value, void *user_data)
{
	uint32_t eip;
	uc_reg_read(uc, UC_X86_REG_EIP, &eip);
	EmuWarning("EIP: 0x%08X: Unmapped Memory Access 0x%08X", eip, address);
	
	uc_emu_stop(uc);
}

uc_engine* EmuX86_Init();

#pragma pack(push, 1)
typedef struct {
	union {
		struct {
			unsigned short limit0;
			unsigned short base0;
			unsigned char base1;
			unsigned char type : 4;
			unsigned char system : 1;      /* S flag */
			unsigned char dpl : 2;
			unsigned char present : 1;     /* P flag */
			unsigned char limit1 : 4;
			unsigned char avail : 1;
			unsigned char is_64_code : 1;  /* L flag */
			unsigned char db : 1;          /* DB flag */
			unsigned char granularity : 1; /* G flag */
			unsigned char base2;
		};
		uint64_t desc;
	};
} SegmentDescriptor;
#pragma pack(pop)

#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

static void init_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
	desc->desc = 0;  //clear the descriptor
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = base >> 24;
	if (limit > 0xfffff) {
		//need Giant granularity
		limit >>= 12;
		desc->granularity = 1;

	}

	desc->limit0 = limit & 0xffff;
	desc->limit1 = limit >> 16;

	//some sane defaults
	desc->dpl = 3;
	desc->present = 1;
	desc->db = 1;   //32 bit
	desc->type = is_code ? 0xb : 3;
	desc->system = 1;  //code or data
}

SegmentDescriptor gdt[32];
uc_x86_mmr gdtr;

void EmuX86_SetupGDT(uc_engine* uc)
{

}

// This is the format of X86 registers on the stack
// Contains a large buffer as this is temporarily used as an actual stack!
typedef struct {
	uint8_t stackData[ONE_MB];
	uint32_t Edi;
	uint32_t Esi;
	uint32_t Ebp;
	uint32_t Esp;
	uint32_t Ebx;
	uint32_t Edx;
	uint32_t Ecx;
	uint32_t Eax;
	uint32_t EFlags;
}x86_reg_dump;

using X87Register = uint8_t[10];

// This is the format of FPU/MMX/SSE state as-saved by the FXSAVE opcode
using XMMRegister = uint8_t[16];
typedef struct {
	uint16_t fcw;  // FPU control word
	uint16_t fsw;  // FPU status word
	uint8_t ftw;  // abridged FPU tag word
	uint8_t reserved_1;
	uint16_t fop;  // FPU opcode
	uint32_t fpu_ip;  // FPU instruction pointer offset
	uint16_t fpu_cs;  // FPU instruction pointer segment selector
	uint16_t reserved_2;
	uint32_t fpu_dp;  // FPU data pointer offset
	uint16_t fpu_ds;  // FPU data pointer segment selector
	uint16_t reserved_3;
	uint32_t mxcsr;  // multimedia extensions status and control register
	uint32_t mxcsr_mask;  // valid bits in mxcsr
	X87Register st[8];
} fpu_reg_dump;

// Temporary X86 state & stack
// Because this is NOT thread safe, we use a lock to make sure only one thread runs unicorn at a time
// This is the a trade-off between performance and stability
x86_reg_dump x86_regs;
fpu_reg_dump fpu_regs;
uint32_t baseEip;
uint32_t baseEsp;
uint32_t returnEip;
uint32_t returnEsp;

void WINAPI EmuX86_ExecWithUnicorn()
{
	uc_engine* uc = EmuX86_Init();

	baseEip -= 5; // Subtract call opcode size from return address, giving us the correct base

	EmuX86_SetupGDT(uc);

	// Sync CPU state to Unicorn
	uc_reg_write(uc, UC_X86_REG_EDI, &x86_regs.Edi);
	uc_reg_write(uc, UC_X86_REG_ESI, &x86_regs.Esi);
	uc_reg_write(uc, UC_X86_REG_EBX, &x86_regs.Ebx);
	uc_reg_write(uc, UC_X86_REG_EDX, &x86_regs.Edx);
	uc_reg_write(uc, UC_X86_REG_ECX, &x86_regs.Ecx);
	uc_reg_write(uc, UC_X86_REG_EAX, &x86_regs.Eax);
	uc_reg_write(uc, UC_X86_REG_EIP, &baseEip);
	uc_reg_write(uc, UC_X86_REG_ESP, &baseEsp);
	uc_reg_write(uc, UC_X86_REG_EBP, &x86_regs.Ebp);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &x86_regs.EFlags);

	// Sync FPU State
	uc_reg_write(uc, UC_X86_REG_FPCW, &fpu_regs.fcw);
	uc_reg_write(uc, UC_X86_REG_FPSW, &fpu_regs.fsw);
	uc_reg_write(uc, UC_X86_REG_FPTAG, &fpu_regs.ftw);	
	for (int i = 0; i < 8; i++) {
		uc_reg_write(uc, UC_X86_REG_FP0 + i, &fpu_regs.st[i]);
	}
	

	uc_err err = uc_emu_start(uc, baseEip, 0, 0, 1);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_emu_start() with error returned: %u\n", err);
	}

	// Write CPU state back to regs struct
	uc_reg_read(uc, UC_X86_REG_EDI, &x86_regs.Edi);
	uc_reg_read(uc, UC_X86_REG_ESI, &x86_regs.Esi);
	uc_reg_read(uc, UC_X86_REG_EBX, &x86_regs.Ebx);
	uc_reg_read(uc, UC_X86_REG_EDX, &x86_regs.Edx);
	uc_reg_read(uc, UC_X86_REG_ECX, &x86_regs.Ecx);
	uc_reg_read(uc, UC_X86_REG_EAX, &x86_regs.Eax);
	uc_reg_read(uc, UC_X86_REG_EIP, &returnEip);
	uc_reg_read(uc, UC_X86_REG_ESP, &returnEsp);
	uc_reg_read(uc, UC_X86_REG_EBP, &x86_regs.Ebp);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &x86_regs.EFlags);

	// Sync FPU State
	uc_reg_read(uc, UC_X86_REG_FPCW, &fpu_regs.fcw);
	uc_reg_read(uc, UC_X86_REG_FPSW, &fpu_regs.fsw);
	uc_reg_read(uc, UC_X86_REG_FPTAG, &fpu_regs.ftw);
	for (int i = 0; i < 8; i++) {
		uc_reg_read(uc, UC_X86_REG_FP0 + i, &fpu_regs.st[i]);
	}
}

// Spinlock implementation that is completely invisible to the caller
static int EmuX86_UnicornLock = 0; 
void __declspec(naked) EmuX86_LockUnicorn()
{
	__asm {
		pushfd
		pushad
	spinlock:
		mov eax, 1
		xchg eax, EmuX86_UnicornLock
		test eax, eax
		jnz spinlock
		popad
		popfd
		ret
	}
}

void __declspec(naked) EmuX86_UnlockUnicorn()
{
	__asm {
		pushfd
		pushad
		xor eax, eax
		xchg eax, EmuX86_UnicornLock
		popad
		popfd
		ret
	}
}

void __declspec(naked) EmuX86_UnicornPatchHandler()
{
	__asm {
		call EmuX86_LockUnicorn	// Lock Unicorn instance

		pop baseEip	// Save EIP that we need to return to, this is used to calculate the start eip of a block
		mov baseEsp, esp // Backup stack pointer
		lea esp, [x86_regs + (ONE_MB + 36)] // Make the stack point to our replacment stack, containing an regs struct
			
		// Call the Unicorn handler, ab(using) our fake stack to sync vcpu state
		fsave fpu_regs	// Save the FPU state
		pushfd	
		pushad
		call EmuX86_ExecWithUnicorn;
		popad	
		popfd
		frstor fpu_regs // Restore the FPU state

		call EmuX86_UnlockUnicorn // Unlock Unicorn instance

		
		mov esp, returnEsp	// Reset the stack pointer to the one returned by unicorn
		push returnEip;	// Make sure we return to the start of the next code block
	
		ret
	}
}

bool EmuX86_DecodeException(LPEXCEPTION_POINTERS e)
{
	// Only decode instructions which reside in the loaded Xbe
	if (e->ContextRecord->Eip > XBE_MAX_VA || e->ContextRecord->Eip < XBE_IMAGE_BASE) {
		return false;
	}

	xbaddr addr = e->ContextRecord->Eip;
	*(uint8_t*)addr = OPCODE_CALL_E8;
	*(uint32_t*)(addr + 1) = (uint32_t)EmuX86_UnicornPatchHandler - addr - 5;
	return true;
}

// Write to Unicorn virtual address space
void EmuX86_Unicorn_Write(xbaddr addr, void* ptr, int size)
{
	if (xbeMirror == nullptr) {
		xbeMirror = malloc(XBE_MAX_VA);
	}

	memcpy((uint8_t*)(xbeMirror)+addr, ptr, size);
}

// Unicorn requires a seperate context per-thread, we handle that by using EmuX86_Init as a GetUnicornContext function
uc_engine* EmuX86_Init()
{
	uc_hook hook_in, hook_out, hook_unmapped;

	// First, attempt to fetch a uncorn instance for the current thread
	auto it = g_UnicornHandles.find(GetCurrentThreadId());
	if (it != g_UnicornHandles.end()) {
		return it->second;
	}
	
	// This thread didn't have a unicorn instance, so create one
	uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_open() with error returned: %u\n", err);
	}

	// Map Xbe space memory into unicorn
	err = uc_mem_map_ptr(uc, XBE_IMAGE_BASE, XBE_MAX_VA - XBE_IMAGE_BASE, UC_PROT_ALL, (void*)((xbaddr)xbeMirror + XBE_IMAGE_BASE));
	if (err) {
		CxbxKrnlCleanup("Failed on uc_mem_map_ptr(uc, 0, XBE_MAX_VA, UC_PROT_ALL, (void*)xbeMirror); with error returned: %u\n", err);
	}

	// Set Unicorn to map 1:1 with our emulated Xbox memory (except XBE Space & HW registers)
	// XBE Space is handled by writing an unpatched Xbe into Unicorn's address space
	err = uc_mem_map_ptr(uc, XBE_MAX_VA, 0xFD000000 - XBE_MAX_VA, UC_PROT_ALL, (void*)XBE_MAX_VA);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_mem_map_ptr(uc, 0, XBOX_MEMORY_SIZE, UC_PROT_ALL, 0) with error returned: %u\n", err);
	}

	// Register MMIO and IO Hooks
	err = uc_mmio_map(uc, 0xFD000000, 0x3000000, read_cb, write_cb, nullptr);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_mmio_map() with error returned: %u\n", err);
	}

	err = uc_hook_add(uc, &hook_in, UC_HOOK_INSN, hook_in_cb, NULL, 1, 0, UC_X86_INS_IN);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_hook_add() with error returned: %u\n", err);
	}

	err = uc_hook_add(uc, &hook_out, UC_HOOK_INSN, hook_out_cb, NULL, 1, 0, UC_X86_INS_OUT);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_hook_add() with error returned: %u\n", err);
	}

	// Log unmapped MMIO
	err = uc_hook_add(uc, &hook_unmapped, UC_HOOK_MEM_UNMAPPED, hook_unmapped_cb, NULL, 1, 0);
	if (err) {
		CxbxKrnlCleanup("Failed on uc_hook_add() with error returned: %u\n", err);
	}

	g_UnicornHandles[GetCurrentThreadId()] = uc;

	return uc;
}

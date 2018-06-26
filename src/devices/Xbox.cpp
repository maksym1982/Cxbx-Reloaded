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
// *   src->devices->Xbox.cpp
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
// *  (c) 2017 Patrick van Logchem <pvanlogchem@gmail.com>
// *  (c) 2018 Luke Usher <luke.usher@outlook.com>
// *
// *  All rights reserved
// *
// ******************************************************************
#include "Xbox.h"
#include "CxbxKrnl\CxbxKrnl.h"
#include "CxbxKrnl\LibRc4.h" 

MCPXRevision Xbox::GetMCPXRevision()
{
	switch (m_HardwareModel) {
	case Revision1_0:
	case Revision1_1:
	case Revision1_2:
	case Revision1_3:
	case Revision1_4:
	case Revision1_5:
	case Revision1_6:
		return MCPXRevision::MCPX_X3;
	case DebugKit:
		// EmuWarning("Guessing MCPXVersion");
		return MCPXRevision::MCPX_X2;
	default:
		// UNREACHABLE(hardwareModel);
		return MCPXRevision::MCPX_X3;
	}
}

SCMRevision Xbox::GetSMCRevision()
{
	switch (m_HardwareModel) {
	case Revision1_0:
		return SCMRevision::P01; // Our SCM returns PIC version string "P01"
	case Revision1_1:
	case Revision1_2:
	case Revision1_3:
	case Revision1_4:
	case Revision1_5:
	case Revision1_6:
		// EmuWarning("Guessing SCMRevision");
		return SCMRevision::P2L; // Assumption; Our SCM returns PIC version string "P05"
	case DebugKit:
		return SCMRevision::D01; // Our SCM returns PIC version string "DXB"
	default:
		// UNREACHABLE(hardwareModel);
		return SCMRevision::P2L;
	}
}

TVEncoder Xbox::GetTVEncoderType()
{
	switch (m_HardwareModel) {
	case Revision1_0:
	case Revision1_1:
	case Revision1_2:
	case Revision1_3:
		return TVEncoder::Conexant;
	case Revision1_4:
		return TVEncoder::Focus;
	case Revision1_5:
		return TVEncoder::Focus; // Assumption
	case Revision1_6:
		return TVEncoder::XCalibur;
	case DebugKit:
		// LukeUsher : My debug kit and at least most of them (maybe all?)
		// are equivalent to v1.0 and have Conexant encoders.
		return TVEncoder::Conexant;
	default: 
		// UNREACHABLE(hardwareModel);
		return TVEncoder::Focus;
	}
}

void Xbox::InitHardware(HardwareModel hardwareModel, IX86CPU* cpu)
{
	// Determine which (revisions of which) components should be used for this hardware model
	MCPXRevision mcpx_revision = GetMCPXRevision();
	SCMRevision smc_revision = GetSMCRevision();
	TVEncoder tv_encoder = GetTVEncoderType();

	// Setup the CPU
	m_pCPU = cpu;
	if (!m_pCPU->IsSupported()) {
		CxbxKrnlCleanup("Given CPU Backend is not supported on the host");
	}

	if (!m_pCPU->Init(this)) {
		CxbxKrnlCleanup("Failed to initialize CPU");
	}

	m_pCPU->Reset();

	// Create busses
	m_pPCIBus = new PCIBus();
	m_pSMBus = new SMBus();

	// Create devices
	m_pMCPX = new MCPXDevice(mcpx_revision);
	m_pSMC = new SMCDevice(smc_revision);
	m_pEEPROM = new EEPROMDevice();
	m_pNVNet = new NVNetDevice();
	m_PNV2A = new NV2ADevice();
	m_pADM1032 = new ADM1032Device();

	// Connect devices to SM bus
	m_pSMBus->ConnectDevice(SMBUS_ADDRESS_SYSTEM_MICRO_CONTROLLER, m_pSMC); // W 0x20 R 0x21
	m_pSMBus->ConnectDevice(SMBUS_ADDRESS_EEPROM, m_pEEPROM); // W 0xA8 R 0xA9

	// TODO : Other SMBus devices to connect
	//g_SMBus->ConnectDevice(SMBUS_ADDRESS_MCPX, g_MCPX); // W 0x10 R 0x11 -- TODO : Is MCPX an SMBus and/or PCI device?
	m_pSMBus->ConnectDevice(SMBUS_ADDRESS_TEMPERATURE_MONITOR, m_pADM1032); // W 0x98 R 0x99
	//g_SMBus->ConnectDevice(SMBUS_ADDRESS_TV_ENCODER, g_TVEncoder); // W 0x88 R 0x89
	switch (tv_encoder) {
	case TVEncoder::Conexant:
		// g_SMBus->ConnectDevice(SMBUS_ADDRESS_TV_ENCODER_ID_CONEXANT, g_TVEncoderConexant); // W 0x8A R 0x8B
		break;
	case TVEncoder::Focus:
		// g_SMBus->ConnectDevice(SMBUS_ADDRESS_TV_ENCODER_ID_FOCUS, g_TVEncoderFocus); // W 0xD4 R 0xD5
		break;
	case TVEncoder::XCalibur:
		// g_SMBus->ConnectDevice(SMBUS_ADDRESS_TV_ENCODER_ID_XCALIBUR, g_TVEncoderXCalibur); // W 0xE0 R 0xE1
		break;
	}

	// Connect devices to PCI bus
	m_pPCIBus->ConnectDevice(PCI_DEVID(0, PCI_DEVFN(1, 1)), m_pSMBus);
	m_pPCIBus->ConnectDevice(PCI_DEVID(0, PCI_DEVFN(4, 0)), m_pNVNet);
	//m_pPCIBus->ConnectDevice(PCI_DEVID(0, PCI_DEVFN(4, 1)), m_pMCPX); // MCPX device ID = 0x0808 ?
	//m_pPCIBus->ConnectDevice(PCI_DEVID(0, PCI_DEVFN(5, 0)), g_NVAPU);
	//m_pPCIBus->ConnectDevice(PCI_DEVID(0, PCI_DEVFN(6, 0)), g_AC97);
	m_pPCIBus->ConnectDevice(PCI_DEVID(1, PCI_DEVFN(0, 0)), m_PNV2A);

	// TODO : Handle other SMBUS Addresses, like PIC_ADDRESS, XCALIBUR_ADDRESS
	// Resources : http://pablot.com/misc/fancontroller.cpp
	// https://github.com/JayFoxRox/Chihiro-Launcher/blob/master/hook.h
	// https://github.com/docbrown/vxb/wiki/Xbox-Hardware-Information
	// https://web.archive.org/web/20100617022549/http://www.xbox-linux.org/wiki/PIC

	// Allocate Physical Memory
	if (m_pPhysicalMemory != nullptr) {
		free(m_pPhysicalMemory);
	}

	m_pPhysicalMemory = (uint8_t*)malloc(128 * ONE_MB);
	if (m_pPhysicalMemory == nullptr) {
		CxbxKrnlCleanup("Failed to allocate Physical Memory");
	}
}

// HLE Bootstrap (Real Xbox bios/Kernel image)
// Uses a user-provided RC4 key to decrypt and execute 2BL
// This means we can boot without an MCPX rom!
// NOTE: This cannot function with GPU-HLE as the Kernel 
// accesses the GPU directly. 
// Saying that, we *may* be able to switch to HLE after boot animation
// during execution by hooking the Xbe loading API.
// NOTE: This currently only supports kernel versions signed for MCPX1.0
// MCPX1.1 uses a different algorithm (TEA) rather than RC4
bool Xbox::LoadBootROM(std::string path, uint8_t* rc4key)
{
	FILE* fp = fopen(path.c_str(), "rb");
	if (fp == nullptr) {
		printf("Xbox::LoadBootROM: Failed to load %s\n", path.c_str());
		return false;
	}

	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	rewind(fp);

	// Check the kernel rom for validity (must be a multiple of 0x10000)
	if (size % 0x10000 != 0) {
		printf("Xbox::LoadBootROM: %s has an invalid size\n", path.c_str());
		return 0;
	}

	m_XboxKernelRom = (uint8_t*)malloc(16 * ONE_MB);
	void* romdata = (uint8_t*)malloc(size);
	if (m_XboxKernelRom == nullptr || romdata == nullptr) {
		printf("Xbox::LoadBootROM: Failed to allocate memory for %s\n", path.c_str());
		return false;
	}

	fread(romdata, 1, size, fp);
	fclose(fp);

	// Fill the KernelRomSpace with our image
	// Image is mirroed throughout the entire 16MB region from 0xFF000000 to 0xFFFFFFFF
	for (uint32_t addr = (uint32_t)(-size); addr >= 0xFF000000; addr -= size) {
		memcpy((void*)&m_XboxKernelRom[addr - 0xFF000000], romdata, size);
	}

	// Use the rc4 key to decrypt 2BL, copy to 0x90000 (Physical Memory)
	Rc4Context context;
	Rc4Initialise(&context, rc4key, 16, 0);
	Rc4Xor(&context, &m_XboxKernelRom[0xFF9E00], &m_pPhysicalMemory[0x90000], 0x6000);

	// Validate that 2BL decrypted correctly by checking the signature at 0x95FE4
	if (*(uint32_t*)&m_pPhysicalMemory[0x95FE4] != 0x7854794A) {
		printf("Xbox::LoadBootROM: Failed to decrypt 2BL. The signature was invalid\n");
		return false;
	}

	// Set the X86 entry point to the value at 0x90000
	uint32_t entryPoint = *((uint32_t*)(&m_pPhysicalMemory[0x90000]));
	m_pCPU->WriteRegister(X86_REG_EIP, entryPoint);
	
	// 2BL will setup the page tables and boot the kernel
	return true;
}

// HLE Bootstrap (Xbox Kernel Executable)
// Loads a user-provided XboxKrnl.exe and sets up emulation to start from entry point
// This can be used to boot the CxbxKrnl replacement 
// This should work with both HLE and LLE code paths.
bool Xbox::LoadKernel(std::string path, XboxKernelKeys& keys)
{
	// TODO: Check if the provided kernel executable is valid
	// TODO: Setup page tables
	// TODO: Load executable into virtual memory
	// TODO: Set the X86 entry point to exe entry point
	return false;
}
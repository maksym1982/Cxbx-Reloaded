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
// *   src->devices->Xbox.h
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
// *
// *  All rights reserved
// *
// ******************************************************************
#pragma once

#include "PCI/PCIBus.h" // For PCIBus
#include "SMBUS/SMBus.h" // For SMBus
#include "SMBUS/SMCDevice.h" // For SMCDevice
#include "SMBUS/EEPROMDevice.h" // For EEPROMDevice
#include "PCI/NVNET/EmuNVNet.h" // For NVNetDevice
#include "SMBUS/ADM1032Device.h" // For ADM1032
#include "PCI/NV2A/nv2a.h" // For NV2ADevice
#include "PCI/MCPXDevice.h" // For MCPXDevice
#include "PCI/AC97/AC97Device.h"
#include "x86\IX86CPU.h"
#include "I8259.h"
#include "I8254.h"

#define SMBUS_ADDRESS_MCPX 0x10 // = Write; Read = 0x11
#define SMBUS_ADDRESS_TV_ENCODER 0x88 // = Write; Read = 0x89
#define SMBUS_ADDRESS_SYSTEM_MICRO_CONTROLLER 0x20 // = Write; Read = 0x21
#define SMBUS_ADDRESS_TV_ENCODER_ID_CONEXANT 0x8A // = Write; Read = 0x8B
#define SMBUS_ADDRESS_TEMPERATURE_MONITOR 0x98 // = Write; Read = 0x99
#define SMBUS_ADDRESS_EEPROM 0xA8 // = Write; Read = 0xA9
#define SMBUS_ADDRESS_TV_ENCODER_ID_FOCUS 0xD4 // = Write; Read = 0xD5
#define SMBUS_ADDRESS_TV_ENCODER_ID_XCALIBUR 0xE0 // = Write; Read = 0xE1

typedef enum {
	Revision1_0,
	Revision1_1,
	Revision1_2,
	Revision1_3,
	Revision1_4,
	Revision1_5,
	Revision1_6,
	DebugKit
} HardwareModel;

typedef enum { // TODO : Move to it's own file
	// http://xboxdevwiki.net/Hardware_Revisions#Video_encoder
	Conexant,
	Focus,
	XCalibur
} TVEncoder;

typedef struct {
	uint8_t EEPROMKey[16];
	uint8_t CertificateKey[16];
} XboxKernelKeys;

class Xbox
{
public:
	// Setup
	void InitHardware(HardwareModel hardwareModel, IX86CPU* cpu);
	bool LoadKernel(std::string path, XboxKernelKeys& keys);
	bool LoadBootROM(std::string path, uint8_t* rc4key);

	// Execution
	void RunFrame();

	// Hardware Devices
	// TODO: Replace this with a generic interface?
	auto GetCPU() { return m_pCPU; };
	auto GetPIC() { return m_pPIC; };
	auto GetPIT() { return m_pPIT; };
	auto GetPCIBus() { return m_pPCIBus; };
	auto GetSMBus() { return m_pSMBus; };
	auto GetMCPX() { return m_pMCPX; };
	auto GetSMC() { return m_pSMC; };
	auto GetEEPROM() { return m_pEEPROM; };
	auto GetNVNet() { return m_pNVNet; };
	auto GetNV2A() { return m_PNV2A; };
	auto GetADM1032() { return m_pADM1032; };
	auto GetAC97Device() { return m_pAC97; };

	// Configuration Info
	TVEncoder GetTVEncoderType();
	SCMRevision GetSMCRevision();
	MCPXRevision GetMCPXRevision();

	// Memory Access (Physical Address Space)
	bool ReadPhysicalMemory(const uint32_t addr, uint32_t& value, const size_t size);
	bool WritePhysicalMemory(const uint32_t addr, const uint32_t value, const size_t size);
	void* GetPhysicalMemoryPtr(const uint32_t addr);
	size_t GetPhysicalMemorySize();

	// IO Devices
	bool IORead(const uint32_t addr, uint32_t& value, const size_t size);
	bool IOWrite(const uint32_t addr, const uint32_t value, const size_t size);
private:
	// Configuration
	HardwareModel m_HardwareModel;

	// Hardware Devices
	// TODO: Replace this with a Map, access via GetDevice functions?
	IX86CPU* m_pCPU;
	I8259* m_pPIC;
	I8254* m_pPIT;
	PCIBus* m_pPCIBus;
	SMBus* m_pSMBus;
	SMCDevice* m_pSMC;
	EEPROMDevice* m_pEEPROM;
	NVNetDevice* m_pNVNet;
	NV2ADevice* m_PNV2A;
	ADM1032Device* m_pADM1032;
	MCPXDevice* m_pMCPX;
	AC97Device* m_pAC97;

	// Other
	uint8_t* m_pPhysicalMemory = nullptr;
	size_t m_PhysicalMemorySize = 0;
	uint8_t m_pXboxKernelRom[0x1000000];
};

extern Xbox* g_pXbox;

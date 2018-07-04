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
// *   src->devices->I8259.cpp
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
// *  Based on QEMU 8259 interrupt controller emulation
// *  (c) 2003-2004 Fabrice Bellard
// *
// *  All rights reserved
// *
// ******************************************************************

#include "I8259.h"
#include "Xbox.h"

#define ICW1 0
#define ICW2 1
#define ICW3 2
#define ICW4 3

#define ICW1_ICW4	0x01		/* ICW4 (not) needed */
#define ICW1_SINGLE	0x02		/* Single (cascade) mode */
#define ICW1_INTERVAL4	0x04	/* Call address interval 4 (8) */
#define ICW1_LEVEL	0x08		/* Level triggered (edge) mode */
#define ICW1_INIT	0x10		/* Initialization - required! */

#define ICW4_8086	0x01		/* 8086/88 (MCS-80/85) mode */
#define ICW4_AUTO	0x02		/* Auto (normal) EOI */
#define ICW4_BUF_SLAVE	0x08	/* Buffered mode/slave */
#define ICW4_BUF_MASTER	0x0C	/* Buffered mode/master */
#define ICW4_SFNM	0x10		/* Special fully nested (not) */

#define PIC_READ_IRR 0			/* OCW3 irq ready next CMD read */
#define PIC_READ_ISR 1			/* OCW3 irq service next CMD read */
#define PIC_EOI 0x20

I8259::I8259(Xbox *pXbox)
{
	m_pXbox = pXbox;
}

void I8259::Reset()
{
	Reset(PIC_MASTER);
	Reset(PIC_SLAVE);

	m_ELCR[PIC_MASTER] = 0;
	m_ELCR[PIC_SLAVE] = 0;

	m_ELCRMask[PIC_MASTER] = 0xF8;
	m_ELCRMask[PIC_SLAVE] = 0xDE;
}

void I8259::Reset(int pic)
{
	m_PreviousIRR[pic] = 0;
	m_IRR[pic] = 0;
	m_IMR[pic] = 0;
	m_ISR[pic] = 0;
	m_PriorityAdd[pic] = 0;
	m_Base[pic] = 0;
	m_ReadRegisterSelect[pic] = 0;
	m_Poll[pic] = false;
	m_SpecialMask[pic] = 0;
	m_InitState[pic] = 0;
	m_AutoEOI[pic] = false;
	m_RotateOnAutoEOI[pic] = false;
	m_IsSpecialFullyNestedMode[pic] = false;
	m_Is4ByteInit[pic] = false;
	UpdateIRQ();
}

void I8259::RaiseIRQ(int index)
{
	if (index <= 7) {
		SetIRQ(PIC_MASTER, index, true);
	} else {
		SetIRQ(PIC_SLAVE, index - 7, true);
	}

	UpdateIRQ();
}

void I8259::LowerIRQ(int index)
{
	if (index <= 7) {
		SetIRQ(PIC_MASTER, index, false);
	} else {
		SetIRQ(PIC_SLAVE, index - 7, false);
	}

	UpdateIRQ();
}

void I8259::SetIRQ(int pic, int index, bool asserted)
{
	int mask = 1 << index;
	
	// Level Triggered
	if (m_ELCR[pic] & mask) {
		if (asserted) {
			m_IRR[pic] |= mask;
			m_PreviousIRR[pic] |= mask;
			return;
		}

		m_IRR[pic] &= ~mask;
		m_PreviousIRR[pic] &= ~mask;
		return;
	}

	// Edge Triggered
	if (asserted) {
		if ((m_PreviousIRR[pic] & mask) == 0) {
			m_IRR[pic] |= mask;
		}

		m_PreviousIRR[pic] |= mask;
		return;
	} 

	m_PreviousIRR[pic] &= ~mask;
}

uint32_t I8259::IORead(uint32_t addr)
{
	if (addr == PORT_PIC_MASTER_ELCR) {
		return m_ELCR[PIC_MASTER];
	}

	if (addr == PORT_PIC_SLAVE_ELCR) {
		return m_ELCR[PIC_SLAVE];
	}

    int pic = (addr & PORT_PIC_SLAVE_COMMAND) == PORT_PIC_SLAVE_COMMAND ? PIC_SLAVE : PIC_MASTER;

    if (m_Poll[pic]) {
        int ret = Poll(pic, addr);
        m_Poll[pic] = 0;
        return ret;
    }

    if ((addr & 1) == 0) {
        if (m_ReadRegisterSelect[pic]) {
            return m_ISR[pic];
        }

        return m_IRR[pic];
    }

    return m_IMR[pic];
}

void I8259::IOWrite(uint32_t addr, uint32_t value)
{
	if (addr == PORT_PIC_MASTER_ELCR) {
		m_ELCR[PIC_MASTER] = value & m_ELCRMask[PIC_MASTER];
		return;
	}

	if (addr == PORT_PIC_SLAVE_ELCR) {
		m_ELCR[PIC_SLAVE] = value & m_ELCRMask[PIC_SLAVE];
		return;
	}

	int pic = (addr & PORT_PIC_SLAVE_COMMAND) == PORT_PIC_SLAVE_COMMAND ? PIC_SLAVE : PIC_MASTER;

	addr &= 1;
	if (addr == 0) {
		if (value & 0x10) {
			Reset(pic);

			m_InitState[pic] = 1;
			m_Is4ByteInit[pic] = value & 1;
			if (value & 0x08) {
				printf("PIC: Level sensitive irq not supported\n");
			}

			return;
		}

		if (value & 0x08) {
			if (value & 0x04) {
				m_Poll[pic] = 1;
			}

			if (value & 0x02) {
				m_ReadRegisterSelect[pic] = value & 1;
			}

			if (value & 0x40) {
				m_SpecialMask[pic] = (value >> 5) & 1;
			}

			return;
		}


		int command = value >> 5;
		int irq = -1;
		int priority = 0;

		switch (command) {
			case 0:
			case 4:
				m_RotateOnAutoEOI[pic] = command >> 2;
				break;
			case 1: /* end of interrupt */
			case 5:
				priority = GetPriority(pic, m_ISR[pic]);
				if (priority != 8) {
					irq = (priority + m_PriorityAdd[pic]) & 7;
					m_ISR[pic] &= ~(1 << irq);

					if (command == 5) {
						m_PriorityAdd[pic] = (irq + 1) & 7;
					}

					UpdateIRQ();
				}
				break;
			case 3:
				irq = value & 7;
				m_ISR[pic] &= ~(1 << irq);
				UpdateIRQ();
				break;
			case 6:
				m_PriorityAdd[pic] = (value + 1) & 7;
				UpdateIRQ();
				break;
			case 7:
				irq = value & 7;
				m_ISR[pic] &= ~(1 << irq);
				m_PriorityAdd[pic] = (irq + 1) & 7;
				UpdateIRQ();
				break;
			default:
				break;
		}
		
		return;
	}

	switch (m_InitState[pic]) {
		case 0:
			/* normal mode */
			m_IMR[pic] = value;
			break;
		case 1:
			m_Base[pic] = value & 0xf8;
			m_InitState[pic] = 2;
			break;
		case 2:
			if (m_Is4ByteInit[pic]) {
				m_InitState[pic] = 3;
				return;
			}
		
			m_InitState[pic] = 0;
			break;
		case 3:
			m_IsSpecialFullyNestedMode[pic] = (value >> 4) & 1;
			m_AutoEOI[pic] = (value >> 1) & 1;
			m_InitState[pic] = 0;
			break;
	}

    return;
}

int I8259::GetCurrentIRQ()
{
    int irq = -1;

    int masterIrq = GetIRQ(PIC_MASTER);
    if (masterIrq >= 0) {
        AcknowledgeIRQ(PIC_MASTER, masterIrq);
        if (masterIrq == 2) {
            int slaveIrq = GetIRQ(PIC_SLAVE);
            if (slaveIrq >= 0) {
                AcknowledgeIRQ(PIC_SLAVE, slaveIrq);
            } else {
                // spurious IRQ on slave controller
                slaveIrq = 7;
            }
            irq = m_Base[PIC_SLAVE] + slaveIrq;
        } else {
            irq = m_Base[PIC_MASTER] + masterIrq;
        }
    } else {
        // spurious IRQ on host controller
        irq = m_Base[PIC_MASTER] + 7;
    }

    UpdateIRQ();
    return irq;
}

int I8259::GetPriority(int pic, uint8_t mask)
{
	if (mask == 0) {
		return 8;
	}

	int priority = 0;
	while ((mask & (1 << ((priority + m_PriorityAdd[pic]) & 7))) == 0) {
		priority++;
	}

	return priority;
}

int I8259::GetIRQ(int pic)
{
	int mask = m_IRR[pic] & ~m_IMR[pic];
	int priority = GetPriority(pic, mask);
	if (priority == 8) {
		return -1;
	}

	mask = m_ISR[pic];

	if (m_SpecialMask[pic]) {
		mask &= ~m_IMR[pic];
	}

	if (m_IsSpecialFullyNestedMode[pic] && pic == PIC_MASTER) {
		mask &= ~(1 << 2);
	}

	int currentPriority = GetPriority(pic, mask);
	if (priority <= currentPriority) {
		return (priority + m_PriorityAdd[pic]) & 7;
	} 
	
	return -1;
}

void I8259::AcknowledgeIRQ(int pic, int index)
{
	if (m_AutoEOI[pic]) {
		if (m_RotateOnAutoEOI[pic]) {
			m_PriorityAdd[pic] = (index + 1) & 7;
		}
	} else {
		m_ISR[pic] |= (1 << index);
	}

	if (!(m_ELCR[pic] & 1 << index)) {
		m_IRR[pic] &= ~(1 << index);
	}
}

uint8_t I8259::Poll(int pic, uint32_t addr)
{
    int irq = GetIRQ(pic);
    if (irq >= 0) {
        if (addr >> 7) {
            m_ISR[PIC_MASTER] &= ~(1 << 2);
            m_ISR[PIC_MASTER] &= ~(1 << 2);
        }

        m_IRR[pic] &= ~(1 << irq);
        m_ISR[pic] &= ~(1 << irq);

        if (addr >> 7 || irq != 2) {
            UpdateIRQ();
        }
    } else {
        addr = 0x07;
        UpdateIRQ();
    }

    return irq;
}

void I8259::UpdateIRQ()
{
	// First, check the slave pic
	int slaveIrq = GetIRQ(PIC_SLAVE);
	if (slaveIrq >= 0) {
	    // If the IRQ was requested on the slave, tell the master
	    SetIRQ(PIC_MASTER, 2, true);
	    SetIRQ(PIC_MASTER, 2, false);
	}

    // Next, check the master
    int masterIrq = GetIRQ(PIC_MASTER);

	if (masterIrq >= 0) {
		m_pXbox->GetCPU()->Interrupt();
	}
}
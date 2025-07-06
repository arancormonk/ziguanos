// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// UART register definitions and constants
// This module contains all hardware register offsets and bit definitions

// Register offsets (from base port)
pub const DATA = 0x00; // Data register (DLAB=0)
pub const IER = 0x01; // Interrupt Enable Register (DLAB=0)
pub const IIR = 0x02; // Interrupt Identification Register (read)
pub const FCR = 0x02; // FIFO Control Register (write)
pub const LCR = 0x03; // Line Control Register
pub const MCR = 0x04; // Modem Control Register
pub const LSR = 0x05; // Line Status Register
pub const MSR = 0x06; // Modem Status Register
pub const SCR = 0x07; // Scratch Register

// Divisor registers (DLAB=1)
pub const DLL = 0x00; // Divisor Latch Low
pub const DLH = 0x01; // Divisor Latch High

// Interrupt Enable Register (IER) bits
pub const IER_RECEIVED_DATA_AVAILABLE = 0x01;
pub const IER_TRANSMIT_HOLDING_EMPTY = 0x02;
pub const IER_RECEIVER_LINE_STATUS = 0x04;
pub const IER_MODEM_STATUS = 0x08;

// Interrupt Identification Register (IIR) bits
pub const IIR_INTERRUPT_PENDING = 0x01;
pub const IIR_INTERRUPT_ID_MASK = 0x0E;
pub const IIR_INTERRUPT_ID_MODEM_STATUS = 0x00;
pub const IIR_INTERRUPT_ID_TRANSMIT_HOLDING_EMPTY = 0x02;
pub const IIR_INTERRUPT_ID_RECEIVED_DATA_AVAILABLE = 0x04;
pub const IIR_INTERRUPT_ID_RECEIVER_LINE_STATUS = 0x06;
pub const IIR_INTERRUPT_ID_CHARACTER_TIMEOUT = 0x0C;

// FIFO Control Register (FCR) bits
pub const FCR_ENABLE_FIFO = 0x01;
pub const FCR_CLEAR_RECEIVE = 0x02;
pub const FCR_CLEAR_TRANSMIT = 0x04;
pub const FCR_DMA_MODE_SELECT = 0x08;
pub const FCR_TRIGGER_1 = 0x00;
pub const FCR_TRIGGER_4 = 0x40;
pub const FCR_TRIGGER_8 = 0x80;
pub const FCR_TRIGGER_14 = 0xC0;

// Line Control Register (LCR) bits
pub const LCR_WORD_LENGTH_5 = 0x00;
pub const LCR_WORD_LENGTH_6 = 0x01;
pub const LCR_WORD_LENGTH_7 = 0x02;
pub const LCR_WORD_LENGTH_8 = 0x03;
pub const LCR_STOP_BITS_1 = 0x00;
pub const LCR_STOP_BITS_2 = 0x04;
pub const LCR_PARITY_NONE = 0x00;
pub const LCR_PARITY_ODD = 0x08;
pub const LCR_PARITY_EVEN = 0x18;
pub const LCR_PARITY_MARK = 0x28;
pub const LCR_PARITY_SPACE = 0x38;
pub const LCR_BREAK_CONTROL = 0x40;
pub const LCR_DLAB = 0x80;

// Modem Control Register (MCR) bits
pub const MCR_DTR = 0x01;
pub const MCR_RTS = 0x02;
pub const MCR_OUT1 = 0x04;
pub const MCR_OUT2 = 0x08;
pub const MCR_LOOPBACK = 0x10;

// Line Status Register (LSR) bits
pub const LSR_DATA_READY = 0x01;
pub const LSR_OVERRUN_ERROR = 0x02;
pub const LSR_PARITY_ERROR = 0x04;
pub const LSR_FRAMING_ERROR = 0x08;
pub const LSR_BREAK_INTERRUPT = 0x10;
pub const LSR_TRANSMIT_HOLDING_EMPTY = 0x20;
pub const LSR_TRANSMIT_EMPTY = 0x40;
pub const LSR_FIFO_ERROR = 0x80;

// Modem Status Register (MSR) bits
pub const MSR_DELTA_CTS = 0x01;
pub const MSR_DELTA_DSR = 0x02;
pub const MSR_TRAILING_EDGE_RI = 0x04;
pub const MSR_DELTA_DCD = 0x08;
pub const MSR_CTS = 0x10;
pub const MSR_DSR = 0x20;
pub const MSR_RI = 0x40;
pub const MSR_DCD = 0x80;

// Common port addresses
pub const COM1_PORT = 0x3F8;
pub const COM2_PORT = 0x2F8;
pub const COM3_PORT = 0x3E8;
pub const COM4_PORT = 0x2E8;

// Common baud rates (divisor values for 115200 base)
pub const BAUD_115200 = 1;
pub const BAUD_57600 = 2;
pub const BAUD_38400 = 3;
pub const BAUD_19200 = 6;
pub const BAUD_9600 = 12;
pub const BAUD_4800 = 24;
pub const BAUD_2400 = 48;
pub const BAUD_1200 = 96;

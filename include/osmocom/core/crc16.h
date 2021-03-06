/*
 * This was copied from the linux kernel and adjusted for our types.
 */
/*
 *	crc16.h - CRC-16 routine
 *
 * Implements the standard CRC-16:
 *   Width 16
 *   Poly  0x8005 (x^16 + x^15 + x^2 + 1)
 *   Init  0
 *
 * Copyright (c) 2005 Ben Gardner <bgardner@wabtec.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2. See the file COPYING for more details.
 */

#pragma once

#include <stdint.h>

#include <sys/types.h>

extern uint16_t const osmo_crc16_table[256];

extern uint16_t osmo_crc16(uint16_t crc, const uint8_t *buffer, size_t len);

static inline uint16_t osmo_crc16_byte(uint16_t crc, const uint8_t data)
{
	return (crc >> 8) ^ osmo_crc16_table[(crc ^ data) & 0xff];
}


/* CCITT polynome 0x8408. This corresponds to x^0 + x^5 + x^12 */

extern uint16_t const osmo_crc16_ccitt_table[256];

extern uint16_t osmo_crc16_ccitt(uint16_t crc, const uint8_t *buffer, size_t len);

static inline uint16_t osmo_crc16_ccitt_byte(uint16_t crc, const uint8_t data)
{
	return (crc >> 8) ^ osmo_crc16_ccitt_table[(crc ^ data) & 0xff];
}

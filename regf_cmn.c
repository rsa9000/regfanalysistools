/**
 * Common functions for regf file analysis
 *
 * Copyright (c) 2016, Sergey Ryazanov <ryazanov.s.a@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "oobmsg.h"
#include "regf_layout.h"
#include "regf_cmn.h"

static inline int __regf_cell_check_basic(const struct regf_cell *cell,
					  unsigned off, const char *cell_type)
{
	if (off % 8) {
		PR_ERR(off, cell_type, "unaligned cell offset\n");
		return -1;
	}

	if (cell->sz > 0) {
		PR_ERR(off, cell_type, "cell is marked as free\n");
		return -1;
	}

	if (cell->sz == 0) {
		PR_ERR(off, cell_type, "zero cell size\n");
		return -1;
	}

	if (-cell->sz % 8) {
		PR_ERR(off, cell_type, "unaligned cell length 0x%08X\n",
		       -cell->sz);
		return -1;
	}

	return 0;
}

static inline int __regf_cell_check_sign(const struct regf_cell *cell,
					 unsigned off, const char *sign)
{
	const char *__sign = (void *)cell->data;

	if (*(uint16_t *)__sign ^ *(uint16_t *)sign) {
		PR_ERR(off, sign, "invalid cell signature %02X %02X (%.2s)\n",
		       __sign[0], __sign[1], __sign);
		return -1;
	}

	return 0;
}

static inline int __regf_cell_check_len(const struct regf_cell *cell,
					unsigned off, const char *cell_type,
					unsigned data_min_len)
{
	unsigned len = (sizeof(*cell) + data_min_len + 7) & ~7;	/* Align */

	if (len > -cell->sz) {
		PR_ERR(off, cell_type,
		       "cell space (0x%08X) is too small for 0x%08X bytes of data\n",
		       -cell->sz - sizeof(*cell), data_min_len);
		return -1;
	}

	return 0;
}

int regf_cell_check(const void *base, unsigned off, const char *cell_type)
{
	const struct regf_cell *cell = base + off;

	return __regf_cell_check_basic(cell, off, cell_type);
}

int regf_cell_check_sign(const void *base, unsigned off, const char *sign)
{
	const struct regf_cell *cell = base + off;

	if (__regf_cell_check_basic(cell, off, sign))
		return -1;

	return __regf_cell_check_sign(cell, off, sign);
}

int regf_cell_check_len(const void *base, unsigned off, const char *cell_type,
			unsigned data_min_len)
{
	const struct regf_cell *cell = base + off;

	if (__regf_cell_check_basic(cell, off, cell_type))
		return -1;

	return __regf_cell_check_len(cell, off, cell_type, data_min_len);
}

int regf_cell_check_sign_len(const void *base, unsigned off, const char *sign,
			     unsigned data_min_len)
{
	const struct regf_cell *cell = base + off;

	if (__regf_cell_check_basic(cell, off, sign))
		return -1;

	if (__regf_cell_check_sign(cell, off, sign))
		return -1;

	return __regf_cell_check_len(cell, off, sign, data_min_len);
}

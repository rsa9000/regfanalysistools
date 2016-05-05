/**
 * Interface for common functions for regf file analysis
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

#ifndef _REGF_CMN_H_
#define _REGF_CMN_H_

int regf_cell_check(const void *base, unsigned off, const char *cell_type);
int regf_cell_check_sign(const void *base, unsigned off, const char *sign);
int regf_cell_check_len(const void *base, unsigned off, const char *cell_type,
			unsigned data_min_len);
int regf_cell_check_sign_len(const void *base, unsigned off, const char *sign,
			     unsigned data_min_len);

#endif	/* _REGF_CMN_H_ */

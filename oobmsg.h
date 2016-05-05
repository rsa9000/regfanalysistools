/**
 * Out of band message printing interface
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

#ifndef __OOBMSG_H_
#define __OOBMSG_H_

void oob_print(const char *fmt, ...);

#define PR_LINE(__fmt, ...)						\
		oob_print(__fmt, ##__VA_ARGS__)
#define __PR_MSG(__type, __cell_off, __cell_type, __fmt, ...)		\
		oob_print(__type ":0x%08X:%s: " __fmt,	\
			  __cell_off, __cell_type, ##__VA_ARGS__)
#define PR_ERR(__cell_off, __cell_type, __fmt, ...)			\
		__PR_MSG("err", __cell_off, __cell_type, __fmt, ##__VA_ARGS__)
#define PR_WARN(__cell_off, __cell_type, __fmt, ...)			\
		__PR_MSG("warn", __cell_off, __cell_type, __fmt, ##__VA_ARGS__)

#endif	/* __OOBMSG_H_ */

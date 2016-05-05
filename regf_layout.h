/**
 * Windows registry file (regf) structures
 *
 * Based on documentation from:
 * https://github.com/libyal/libregf/blob/master/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
 * https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
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

#ifndef _REGF_LAYOUT_H_
#define _REGF_LAYOUT_H_

#include <stdint.h>

/* File header */
struct regf_fhdr {
/* 00 */char sign[4];		/* "regf" string */
/* 04 */uint32_t seqno_pri;	/* primary seqno */
/* 08 */uint32_t seqno_sec;	/* secondary seqno */
/* 0C */uint64_t timestamp;
/* 14 */uint32_t ver_maj;
/* 18 */uint32_t ver_min;
/* 1C */uint32_t is_log;	/* is this logfile */
/* 20 */uint32_t __unkn_0020;
/* 24 */uint32_t root_off;	/* root key offset */
/* 28 */uint32_t data_sz;	/* data size */
/* 2C */uint32_t __unkn_002C;
};

/* hbin header */
struct regf_hbin {
/* 00 */char sign[4];		/* "hbin" string */
/* 04 */uint32_t off;		/* Offset of this hbin inside file data region */
/* 08 */uint32_t sz;		/* hbin size */
/* 0C */uint32_t __unkn_0C;
/* 10 */uint32_t __unkn_10;
/* 14 */uint64_t timestamp;	/* hbin timestamp */
/* 1C */uint32_t __unkn_1C;
/* 20 */uint8_t data[];
};

/* hbin cell header */
struct regf_cell {
/* 00 */int32_t sz;		/* Positive for free cell and negative for allocated */
/* 04 */uint8_t data[];
};

#define REGF_NK_F_VOLATILE	0x0001	/* Key is volatile */
#define REGF_NK_F_EXIT		0x0002	/* Key is mount point */
#define REGF_NK_F_ENTRY		0x0004	/* Key is root */
#define REGF_NK_F_NODEL		0x0008	/* Key can not be deleted */
#define REGF_NK_F_SYMLINK	0x0010	/* Key is symbolic link */
#define REGF_NK_F_ASCII		0x0020	/* Key name is in ASCII */
#define REGF_NK_F_PREDEF	0x0040	/* Key is predefined handle */
#define REGF_NK_F_KNOWN_M	0x007F	/* Mask of known flags */

/* named key (nk) */
struct regf_nk {
/* 00 */char sign[2];		/* "nk" signature */
/* 02 */uint16_t flags;		/* see REGF_NK_F_xxx */
/* 04 */uint64_t timestamp;	/* Last write timestamp */
/* 0C */uint32_t __unkn_0C;
/* 10 */uint32_t parent_off;	/* Parent key offset */
/* 14 */uint32_t skey_num;	/* Number of subkeys */
/* 18 */uint32_t vskey_num;	/* Number of volatile subkeys */
/* 1C */uint32_t skey_off;	/* Subkeys list offset */
/* 20 */uint32_t vskey_off;	/* Volatile subkeys list offset */
/* 24 */uint32_t val_num;	/* Number of values */
/* 28 */uint32_t val_off;	/* Values list offset */
/* 2C */uint32_t sec_off;	/* Security key offset */
/* 30 */uint32_t cname_off;	/* Class name offset */
/* 34 */uint32_t skey_name_max;	/* Largest subkey name size */
/* 38 */uint32_t skey_cname_max;/* Largest subkey class name size */
/* 3C */uint32_t val_name_max;	/* Largest value name size */
/* 40 */uint32_t val_data_max;	/* Largest value data size */
/* 44 */uint32_t __unkn_44;
/* 48 */uint16_t name_sz;	/* Key name size */
/* 4C */uint16_t cname_sz;	/* Class name size */
/* 50 */char name[];		/* Key name (UNICODE or ASCII) */
};

/* security key (sk) */
struct regf_sk {
/* 00 */char sign[2];		/* "sk" signature */
/* 02 */uint16_t __unkn_00;
/* 04 */uint32_t prev;		/* Previous offset */
/* 08 */uint32_t next;		/* Next offset */
/* 0C */uint32_t refcnt;	/* Reference count */
/* 10 */uint8_t desc[];		/* Security descriptor */
};

#define REGF_VK_T_NONE		0x0000
#define REGF_VK_T_SZ		0x0001	/* aka REG_SZ, string */
#define REGF_VK_T_EXPAND_SZ	0x0002	/* aka REG_EXPAND_SZ, expand string */
#define REGF_VK_T_BINARY	0x0003	/* aka REG_BINARY, dinary data */
#define REGF_VK_T_DWORD		0x0004	/* aka REG_DWORD, little endian DWORD */
#define REGF_VK_T_DWORD_BE	0x0005	/* aka REG_DWORD_BIG_ENDIAN, bit endian DWORD */
#define REGF_VK_T_LINK		0x0006	/* aka REG_LINK */
#define REGF_VK_T_MULTI_SZ	0x0007	/* aka REG_MULTI_SZ, array of string */
#define REGF_VK_T_RES_LST	0x0008	/* aka REG_RESOURCE_LIST, resource list */
#define REGF_VK_T_RES_DESC	0x0009	/* aka REG_FULL_RESOURCE_DESCRIPTOR, resource descriptor */
#define REGF_VK_T_RES_REQ	0x000A	/* aka REG_RESOURCE_REQUIREMENTS_LIST */
#define REGF_VK_T_QWORD		0x000B	/* aka REG_QWORD, 64-bit integer */

#define REGF_VK_F_ASCII		0x0001	/* Name is in ASCII */

/* value key (vk) */
struct regf_vk {
/* 00 */char sign[2];		/* "vk" signature */
/* 02 */uint16_t name_sz;	/* Key name size */
/* 04 */uint32_t sz;		/* Data size */
/* 08 */uint32_t off;		/* Data offset */
/* 0C */uint32_t type;		/* Data type */
/* 10 */uint16_t flags;
/* 12 */uint16_t __unkn_12;
/* 14 */char name[];		/* Value name */
};

/* data block (db) */
struct regf_db {
/* 00 */char sign[2];		/* "db" signature */
/* 02 */uint16_t nsegm;		/* Number of segments */
/* 04 */uint32_t segm_off;	/* Segments list offset */
};

/* keys list header */
struct regf_lst {
/* 00 */char sign[2];		/* "lf" or "lh" or "li" or "ri" signature */
/* 02 */uint16_t nelem;		/* Number of elements */
/* 04 */uint8_t data[];		/* List elements */
};

/* "lf" fast leaf element (with name hints) */
struct regf_lf_elem {
/* 00 */uint32_t off;		/* Key offset */
/* 04 */char hint[4];		/* Key name hint (4 chars of name) */
};

/* "lh" hash leaf element (with name hash) */
struct regf_lh_elem {
/* 00 */uint32_t off;		/* Key offset */
/* 04 */uint32_t hash;		/* Key hame hash */
};

/* "li" list elemenent */
struct regf_li_elem {
/* 00 */uint32_t off;		/* Key offset */
};

/* "ri" list elemenent */
struct regf_ri_elem {
/* 00 */uint32_t off;		/* Sublist offset */
};

#endif	/* _REGF_LAYOUT_H_ */

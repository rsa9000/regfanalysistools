/**
 * Print registry file (regf) as tree utility
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

#include <stdio.h>
#include <errno.h>
#include <wchar.h>
#include <iconv.h>
#include <locale.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <sys/mman.h>

#include "oobmsg.h"
#include "rbtree.h"
#include "regf_cmn.h"
#include "regf_layout.h"

/* Bitmask of cell types (from parent POV) */
#define CT_FREE		0x0001
#define CT_NK		0x0002
#define CT_SK		0x0004
#define CT_CNAME	0x0008
#define CT_LST		0x0010
#define CT_VLST		0x0020
#define CT_VK		0x0040
#define CT_DATA		0x0080
#define CT_DB		0x0100
#define CT_SLST		0x0200
#define CT_DATAS	0x0400

struct cell {
	struct rbtree_head tree;
	unsigned len;
	unsigned refcnt;
	unsigned type;		/* Ref types map */
};

#define VER_1_3		0x13
#define VER_1_5		0x15

/* Regdump state container */
static struct state {
	iconv_t icd;		/* iconv descriptor */
	void *__data;		/* Mapped to mem regf hbin data */
	const void *data;	/* Pointer for reading operations */
	unsigned version;	/* Combined maj & min parts: maj << 8 | min */
	uint32_t root_off;
	uint32_t data_sz;
	struct rbtree cells;
} st;

static struct cell *cache_cell_alloc(unsigned off, unsigned len)
{
	struct cell *c = calloc(1, sizeof(*c));

	c->tree.key = off;
	c->len = len;

	rbtree_insert(&st.cells, &c->tree);

	return c;
}

static struct cell *cache_cell_find(unsigned off)
{
	struct rbtree_head *node = rbtree_lookup(&st.cells, off);

	return rbt_is_nil(&st.cells, node) ? NULL :
	       rbtree_entry(node, struct cell, tree);
}

static void cache_cell_updref(struct cell *cell, unsigned type)
{
	cell->refcnt++;
	cell->type |= type;
}

static int regf_parse_fheader(FILE *fp)
{
	uint8_t buf[0x200];
	const struct regf_fhdr *fhdr = (void *)buf;
	const uint32_t *p32;
	uint32_t cs;
	int i, res;

	if (fseek(fp, 0, SEEK_SET)) {
		fprintf(stderr, "%s: could not seek to header position: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	res = fread(buf, 1, sizeof(buf), fp);
	if (res != sizeof(buf)) {
		fprintf(stderr, "%s: could not read file header page: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	if (strncmp(fhdr->sign, "regf", 4) != 0) {
		fprintf(stderr, "%s: unexpected signature '%.4s' expect 'regf'\n",
			__func__, fhdr->sign);
		return -1;
	}

	cs = 0;
	for (i = 0, p32 = (void *)buf; i < 0x200/sizeof(uint32_t); ++i, ++p32)
		cs ^= *p32;

	if (cs) {
		fprintf(stderr, "%s: header checksum verification failed\n",
			__func__);
		return -1;
	}

	printf("fhdr.seqno{pri,sec} = 0x%08X, 0x%08X\n", fhdr->seqno_pri, fhdr->seqno_sec);
	printf("fhdr.timestamp = 0x%016"PRIX64"\n", fhdr->timestamp);
	printf("fhdr.logfile = %s\n", fhdr->is_log ? "true" : "false");

	if (fhdr->seqno_pri != fhdr->seqno_sec) {
		fprintf(stderr, "%s: primary/secondary seqno missmatch!\n",
			__func__);
		return -1;
	}

	st.version = fhdr->ver_maj << 4 | fhdr->ver_min;
	st.root_off = fhdr->root_off;
	st.data_sz = fhdr->data_sz;

	printf("fhdr.version = %u.%u\n", fhdr->ver_maj, fhdr->ver_min);

	printf("fhdr.root_off = 0x%08X\n", fhdr->root_off);
	printf("fhdr.data_sz = 0x%08X\n", fhdr->data_sz);

	return 0;
}

static int regf_parse_nk(const char *pref, unsigned off);
static int regf_parse_sk(const char *pref, unsigned off);
static int regf_parse_vk(const char *pref, unsigned off);
static int regf_parse_db(const char *pref, unsigned off);
static int regf_parse_raw(const char *pref, unsigned off, unsigned type,
			  unsigned len);
static int regf_parse_lst(const char *pref, unsigned off, int have_vals);

static const char *regf_hexdump(const void *ptr, unsigned len)
{
#define __MAX_LEN	16
	static char buf[__MAX_LEN * 3 + 4 + 1];
	char *p = buf, *e = buf + sizeof(buf);
	const uint8_t *a = ptr;
	unsigned i, __len;

	__len = len > __MAX_LEN ? __MAX_LEN : len;
	for (i = 0; i < __len; ++i)
		p += snprintf(p, e - p, " %02X", a[i]);

	if (__len != len)
		p += snprintf(p, e - p, " ...");

	return &buf[1];
#undef __MAX_LEN
}

static const wchar_t *regf_unicode2wchar(const void *ptr, unsigned len)
{
#define __MAX_LEN	50
	static wchar_t __obuf[__MAX_LEN + 4 + 1];
	uint16_t __ibuf[__MAX_LEN * 2];
	unsigned __len;
	char *ibuf = (char *)__ibuf;
	char *obuf = (char *)__obuf;
	size_t ilen, olen, res;

	__len = len / 2 > __MAX_LEN ? __MAX_LEN : len / 2;

	memcpy(__ibuf, ptr, __len * sizeof(__ibuf[0]));

	ilen = __len * sizeof(__ibuf[0]);
	olen = __len * sizeof(__obuf[0]);

	iconv(st.icd, NULL, NULL, NULL, NULL);	/* Reset descriptor */

	res = iconv(st.icd, &ibuf, &ilen, &obuf, &olen);
	if (res == (size_t)-1)
		return L"<error>";

	if (__len != len / 2) {
		__obuf[__MAX_LEN + 0] = '.';
		__obuf[__MAX_LEN + 1] = '.';
		__obuf[__MAX_LEN + 2] = '.';
		__obuf[__MAX_LEN + 3] = '\0';
	} else {
		__obuf[__len] = '\0';
	}

	return __obuf;
#undef __MAX_LEN
}

static const char *regf_dword2str(const void *ptr, unsigned len)
{
	static char buf[0x20];

	if (len == 0) {
		return "0";
	} else if (len == 4) {
		snprintf(buf, sizeof(buf), "0x%08X (%d)", *(uint32_t *)ptr,
			 *(int32_t *)ptr);
		return buf;
	}

	return "<invalid length>";
}

static const char *regf_qword2str(const void *ptr, unsigned len)
{
	static char buf[0x40];

	if (len == 0) {
		return "0";
	} else if (len == 8) {
		snprintf(buf, sizeof(buf), "0x%016"PRIX64" (%"PRId64")",
			 *(uint64_t *)ptr, *(int64_t *)ptr);
		return buf;
	}

	return "<invalid length>";
}

static int regf_print_data(const char *pref, const void *p, unsigned type,
			   unsigned len)
{
	switch (type) {
	case REGF_VK_T_DWORD:
		printf("%s%s\n", pref, regf_dword2str(p, len));
		break;
	case REGF_VK_T_QWORD:
		printf("%s%s\n", pref, regf_qword2str(p, len));
		break;
	case REGF_VK_T_SZ:
	case REGF_VK_T_EXPAND_SZ:
		printf("%s%ls\n", pref, regf_unicode2wchar(p, len));
		break;
	default:
		printf("%s%s\n", pref, regf_hexdump(p, len));
		break;
	}

	return 0;
}

static int regf_parse_vlst(const char *pref, unsigned off, unsigned num)
{
#define VLST_PR_WARN(__fmt, ...)	PR_WARN(off, "vlst", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const uint32_t *vals = (void *)rc->data;
	size_t pref_len = strlen(pref);
	char __pref[pref_len + 4];
	struct cell *cell;
	unsigned i;
	int res, ret = 0;

	if (regf_cell_check_len(st.data, off, "vlst", num * sizeof(vals[0])))
		return -1;

	for (i = 0; i < num; ++i) {
		cell = cache_cell_find(vals[i]);
		if (!cell) {
			VLST_PR_WARN("could not find value cell 0x%08X\n",
				     vals[i]);
			ret = -1;
			continue;
		}
		cache_cell_updref(cell, CT_VK);
		if (i == num - 1) {
			printf("%s '-", pref);
			snprintf(__pref, sizeof(__pref), "%s   ", pref);
		} else {
			printf("%s +-", pref);
			snprintf(__pref, sizeof(__pref), "%s | ", pref);
		}
		res = regf_parse_vk(__pref, vals[i]);
		if (res) {
			VLST_PR_WARN("could not parse value key in cell 0x%08X\n",
				     vals[i]);
			ret = -1;
			continue;
		}
	}

	return ret;
}

static int regf_parse_nk(const char *pref, unsigned off)
{
#define NK_PR_WARN(__fmt, ...)	PR_WARN(off, "nk", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_nk *nk = (void *)rc->data;
	struct cell *cell;
	int res, ret = 0;

	if (regf_cell_check_sign_len(st.data, off, "nk", sizeof(*nk)))
		return -1;

	if (nk->flags & REGF_NK_F_ASCII)
		printf("[%.*s]\n", nk->name_sz, nk->name);
	else
		printf("[%ls]\n", regf_unicode2wchar(nk->name, nk->name_sz));

	if (!(nk->flags & REGF_NK_F_ENTRY)) {
		cell = cache_cell_find(nk->parent_off);
		if (!cell) {
			NK_PR_WARN("could not find parent cell 0x%08X\n",
				   nk->parent_off);
			ret = -1;
		} else {
			cache_cell_updref(cell, CT_NK);
		}
	}

	if (nk->cname_off != ~0U) {
		cell = cache_cell_find(nk->cname_off);
		if (!cell) {
			NK_PR_WARN("could not find class name cell 0x%08X\n",
				   nk->cname_off);
			ret = -1;
		} else {
			cache_cell_updref(cell, CT_CNAME);
		}
	}

	cell = cache_cell_find(nk->sec_off);
	if (!cell) {
		NK_PR_WARN("could not find security descriptor cell 0x%08X\n",
			   nk->sec_off);
		ret = -1;
	} else {
		cache_cell_updref(cell, CT_SK);
		res = regf_parse_sk(pref, nk->sec_off);
		if (res) {
			NK_PR_WARN("could not parse security key cell at 0x%08X\n",
				   nk->sec_off);
			ret = -1;
		}
	}

	if (nk->skey_num) {
		cell = cache_cell_find(nk->skey_off);
		if (!cell) {
			NK_PR_WARN("could not find subkeys list cell 0x%08X\n",
				   nk->skey_off);
			ret = -1;
		} else {
			cache_cell_updref(cell, CT_LST);
			res = regf_parse_lst(pref, nk->skey_off, nk->val_num ? 1 : 0);
			if (res) {
				NK_PR_WARN("could not parse subkeys list at 0x%08X\n",
					   nk->skey_off);
				ret = -1;
			}
		}
	}

	if (nk->val_num) {
		cell = cache_cell_find(nk->val_off);
		if (!cell) {
			NK_PR_WARN("could not find values list cell 0x%08X\n",
				   nk->val_off);
			ret = -1;
		} else {
			cache_cell_updref(cell, CT_VLST);
			res = regf_parse_vlst(pref, nk->val_off, nk->val_num);
			if (res) {
				NK_PR_WARN("could not parse values list cell 0x%08X\n",
					   nk->val_off);
				ret = -1;
			}
		}
	}

	return ret;
}

static int regf_parse_sk(const char *pref, unsigned off)
{
	const struct regf_cell *rc = st.data + off;
	const struct regf_sk *sk = (void *)rc->data;

	if (regf_cell_check_sign_len(st.data, off, "sk", sizeof(*sk)))
		return -1;

	/* Do not print anything */

	return 0;
}

static const char *regf_parse_vk_type(uint32_t type)
{
	switch (type) {
	case REGF_VK_T_NONE: return "REG_NONE";
	case REGF_VK_T_SZ: return "REG_SZ";
	case REGF_VK_T_EXPAND_SZ: return "REG_EXPAND_SZ";
	case REGF_VK_T_BINARY: return "REG_BINARY";
	case REGF_VK_T_DWORD: return "REG_DWORD";
	case REGF_VK_T_DWORD_BE: return "REG_DWORD_BIG_ENDIAN";
	case REGF_VK_T_LINK: return "REG_LINK";
	case REGF_VK_T_MULTI_SZ: return "REG_MULTI_SZ";
	case REGF_VK_T_RES_LST: return "REG_RESOURCE_LIST";
	case REGF_VK_T_RES_DESC: return "REG_FULL_RESOURCE_DESCRIPTOR";
	case REGF_VK_T_RES_REQ: return "REG_RESOURCE_REQUIREMENTS_LIST";
	case REGF_VK_T_QWORD: return "REG_QWORD";
	}
	return "UNKNOWN";
}

static int regf_parse_vk(const char *pref, unsigned off)
{
#define VK_PR_WARN(__fmt, ...)	PR_WARN(off, "vk", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_vk *vk = (void *)rc->data;
	size_t pref_len = strlen(pref);
	char __pref[pref_len + 3];
	struct cell *cell;
	int res, pos = strlen(pref);
	const wchar_t *__name;

	if (regf_cell_check_sign_len(st.data, off, "vk", sizeof(*vk)))
		return -1;

	if (!vk->name_sz) {
		pos += printf("(default)");
	} else if (vk->flags & REGF_VK_F_ASCII) {
		pos += printf("%.*s", vk->name_sz, vk->name);
	} else {
		__name = regf_unicode2wchar(vk->name, vk->name_sz);
		pos += wcslen(__name);
		printf("%ls", __name);
	}

	if (pos < 60)
		pos += printf("%*s", 60 - pos, " ");
	printf(" %-10s (0x%02X)", regf_parse_vk_type(vk->type),
	       vk->sz & ~0x80000000);

	if (vk->sz & 0x80000000) {	/* Embedded data */
		if ((vk->sz & ~0x80000000) > 4) {
			printf("\n");
			VK_PR_WARN("value legnth 0x%08X too big for embeded data\n",
				   vk->sz & ~0x80000000);
			return -1;
		}
		res = regf_print_data(" ", &vk->off, vk->type,
				      vk->sz & ~0x80000000);
		if (res) {
			VK_PR_WARN("could not parse embeded data\n");
			return -1;
		}
		return 0;
	}

	cell = cache_cell_find(vk->off);
	if (!cell) {
		printf("\n");
		VK_PR_WARN("could not find raw data cell 0x%08X\n", vk->off);
		return -1;
	}

	/**
	 * Data occupates only one cell if it small, also data blocks
	 * supported in 1.5
	 */
	if (vk->sz <= 16344 || st.version < VER_1_5) {
		cache_cell_updref(cell, CT_DATA);
		res = regf_parse_raw(" ", vk->off, vk->type, vk->sz);
		if (res) {
			VK_PR_WARN("could not parse raw data in cell 0x%08X\n",
				   vk->off);
			return -1;
		}
	} else {
		cache_cell_updref(cell, CT_DB);
		res = regf_parse_db(__pref, vk->off);
		if (res) {
			VK_PR_WARN("could not parse data block in cell 0x%08X\n",
				   vk->off);
			return -1;
		}
	}

	return 0;
}

static int regf_parse_lst_lf(const char *pref, unsigned off, int have_vals)
{
#define LF_PR_WARN(__fmt, ...)	PR_WARN(off, "lf", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_lst *lst = (void *)rc->data;
	const struct regf_lf_elem *elems = (void *)lst->data;
	size_t pref_len = strlen(pref);
	char __pref[pref_len + 4];
	struct cell *cell;
	int i, res, ret = 0;

	for (i = 0; i < lst->nelem; ++i) {
		cell = cache_cell_find(elems[i].off);
		if (!cell) {
			LF_PR_WARN("could not find key cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
		cache_cell_updref(cell, CT_NK);
		if (i == lst->nelem - 1 && !have_vals) {
			printf("%s '-", pref);
			snprintf(__pref, sizeof(__pref), "%s   ", pref);
		} else {
			printf("%s +-", pref);
			snprintf(__pref, sizeof(__pref), "%s | ", pref);
		}
		res = regf_parse_nk(__pref, elems[i].off);
		if (res) {
			LF_PR_WARN("could not parse subkey in cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
	}

	return ret;
}

static int regf_parse_lst_lh(const char *pref, unsigned off, int have_vals)
{
#define LH_PR_WARN(__fmt, ...)	PR_WARN(off, "lh", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_lst *lst = (void *)rc->data;
	const struct regf_lh_elem *elems = (void *)lst->data;
	size_t pref_len = strlen(pref);
	char __pref[pref_len + 4];
	struct cell *cell;
	int i, res, ret = 0;

	snprintf(__pref, sizeof(__pref), "%s  ", pref);

	for (i = 0; i < lst->nelem; ++i) {
		cell = cache_cell_find(elems[i].off);
		if (!cell) {
			LH_PR_WARN("could not find key cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
		cache_cell_updref(cell, CT_NK);
		if (i == lst->nelem - 1 && !have_vals) {
			printf("%s '-", pref);
			snprintf(__pref, sizeof(__pref), "%s   ", pref);
		} else {
			printf("%s +-", pref);
			snprintf(__pref, sizeof(__pref), "%s | ", pref);
		}
		res = regf_parse_nk(__pref, elems[i].off);
		if (res) {
			LH_PR_WARN("could not parse subkey in cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
	}

	return ret;
}

static int regf_parse_lst_li(const char *pref, unsigned off, int have_vals)
{
#define LI_PR_WARN(__fmt, ...)	PR_WARN(off, "li", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_lst *lst = (void *)rc->data;
	const struct regf_li_elem *elems = (void *)lst->data;
	size_t pref_len = strlen(pref);
	char __pref[pref_len + 4];
	struct cell *cell;
	int i, res, ret = 0;

	snprintf(__pref, sizeof(__pref), "%s  ", pref);

	for (i = 0; i < lst->nelem; ++i) {
		cell = cache_cell_find(elems[i].off);
		if (!cell) {
			LI_PR_WARN("could not find key cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
		cache_cell_updref(cell, CT_NK);
		if (i == lst->nelem - 1 && !have_vals) {
			printf("%s '-", pref);
			snprintf(__pref, sizeof(__pref), "%s   ", pref);
		} else {
			printf("%s +-", pref);
			snprintf(__pref, sizeof(__pref), "%s | ", pref);
		}
		res = regf_parse_nk(__pref, elems[i].off);
		if (res) {
			LI_PR_WARN("could not parse subkey in cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
	}

	return ret;
}

static int regf_parse_lst_ri(const char *pref, unsigned off, int have_vals)
{
#define RI_PR_WARN(__fmt, ...)	PR_WARN(off, "ri", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_lst *lst = (void *)rc->data;
	const struct regf_ri_elem *elems = (void *)lst->data;
	struct cell *cell;
	int i, res, ret = 0;

	for (i = 0; i < lst->nelem; ++i) {
		cell = cache_cell_find(elems[i].off);
		if (!cell) {
			RI_PR_WARN("could not find keys list cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
		cache_cell_updref(cell, CT_LST);
		res = regf_parse_lst(pref, elems[i].off, have_vals);
		if (res) {
			RI_PR_WARN("could not parse subkey list in cell 0x%08X\n",
				   elems[i].off);
			ret = -1;
			continue;
		}
	}

	return ret;
}

static int regf_parse_lst(const char *pref, unsigned off, int have_vals)
{
	const struct regf_cell *rc = st.data + off;
	const struct regf_lst *lst = (void *)rc->data;

	if (regf_cell_check_len(st.data, off, "lst", sizeof(*lst)))
		return -1;

	if (strncmp(lst->sign, "lf", 2) == 0) {
		return regf_parse_lst_lf(pref, off, have_vals);
	} else if (strncmp(lst->sign, "lh", 2) == 0) {
		return regf_parse_lst_lh(pref, off, have_vals);
	} else if (strncmp(lst->sign, "li", 2) == 0) {
		return regf_parse_lst_li(pref, off, have_vals);
	} else if (strncmp(lst->sign, "ri", 2) == 0) {
		return regf_parse_lst_ri(pref, off, have_vals);
	} else {
		PR_ERR(off, "lst", "unexpected list signature\n");
		return -1;
	}

	return 0;
}

static int regf_parse_slst(const char *pref, unsigned off, unsigned num)
{
#define SLST_PR_WARN(__fmt, ...)PR_WARN(off, "slst", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const uint32_t *segs = (void *)rc->data;
	struct cell *cell;
	int i, ret = 0;

	if (regf_cell_check_len(st.data, off, "slst", num * sizeof(segs[0])))
		return -1;

	for (i = 0; i < num; ++i) {
		cell = cache_cell_find(segs[i]);
		if (!cell) {
			SLST_PR_WARN("could not find data segment cell 0x%08X\n",
				     segs[i]);
			ret = -1;
			continue;
		}
		cache_cell_updref(cell, CT_DATAS);
	}

	return ret;
}

static int regf_parse_raw(const char *pref, unsigned off, unsigned type, unsigned len)
{
	const struct regf_cell *rc = st.data + off;

	if (regf_cell_check_len(st.data, off, "data", len))
		return -1;

	return regf_print_data(pref, rc->data, type, len);
}

static int regf_parse_db(const char *pref, unsigned off)
{
#define DB_PR_WARN(__fmt, ...)	PR_WARN(off, "db", __fmt, ##__VA_ARGS__)
	const struct regf_cell *rc = st.data + off;
	const struct regf_db *db = (void *)rc->data;
	char __pref[0x10];
	struct cell *cell;
	int res;

	if (regf_cell_check_sign_len(st.data, off, "db", sizeof(*db)))
		return -1;

	if (db->nsegm) {
		cell = cache_cell_find(db->segm_off);
		if (!cell) {
			printf("\n");
			DB_PR_WARN("could not find segments list cell 0x%08X\n",
				   db->segm_off);
			return -1;
		}
		cache_cell_updref(cell, CT_SLST);
		snprintf(__pref, sizeof(__pref), "%s  ", pref);
		res = regf_parse_slst(__pref, db->segm_off, db->nsegm);
		if (res) {
			DB_PR_WARN("could not parse segments list cell 0x%08X\n",
				   db->segm_off);
			return -1;
		}
	}

	return 0;
}

static int regf_parse_root(void)
{
	struct cell *cell;

	cell = cache_cell_find(st.root_off);
	if (!cell) {
		PR_ERR(st.root_off, "root", "could not find root key cell\n",
		       st.root_off);
		return -1;
	}
	cache_cell_updref(cell, CT_NK);

	return regf_parse_nk("", st.root_off);
}

static int regf_scan_data(const void *data, unsigned data_sz)
{
	const struct regf_hbin *hbin;
	const struct regf_cell *rc;
	struct cell *cell;
	unsigned hoff, cell_sz;

	for (hbin = data, hoff = 0;
	     hoff < data_sz;
	     hoff += hbin->sz, hbin = (void *)hbin + hbin->sz) {
		if (strncmp(hbin->sign, "hbin", 4) != 0) {
			fprintf(stderr, "hbin signature missed at 0x%08X\n",
				(unsigned)((void *)hbin - (void *)data));
			return -1;
		}

		for (rc = (void *)hbin->data;
		     (void *)rc < (void *)hbin + hbin->sz;
		     rc = (void *)rc + cell_sz) {
			cell_sz = rc->sz > 0 ? rc->sz : -rc->sz;
			cell = cache_cell_alloc((void *)rc - (void *)data, cell_sz);
			if (rc->sz > 0)
				cell->type = CT_FREE;
		}
	}

	return 0;
}

static void regf_cells_stat(void)
{
	struct cell *cell;
	int cnt_tot = 0, cnt_free = 0, cnt_orph = 0;

	rbt_inorder_walk_entry(cell, &st.cells, tree) {
		cnt_tot++;
		if (cell->type & CT_FREE) {
			cnt_free++;
			if (cell->type & ~CT_FREE || cell->refcnt)
				PR_WARN(cell->tree.key, "unkn", "someone reference free cell (type = 0x%04X, cnt = %u)\n",
					cell->type, cell->refcnt);
			continue;
		}
		if (cell->refcnt == 0) {
			PR_WARN(cell->tree.key, "unkn", "orphaned cell\n");
			cnt_orph++;
		}
		if (cell->type & (cell->type - 1)) {
			PR_WARN(cell->tree.key, "unkn", "cell referenced in different ways (type = 0x%04X, cnt = %u)\n",
				cell->type, cell->refcnt);
			continue;
		}
		if (cell->type & ~(CT_NK | CT_SK) && cell->refcnt > 1) {
			PR_WARN(cell->tree.key, "unkn", "cell referenced multiple times (type = 0x%04X, cnt = %u)\n",
				cell->type, cell->refcnt);
			continue;
		}
	}

	PR_LINE("Total cells: %d, free cell: %d, orphaned cells: %d\n",
		cnt_tot, cnt_free, cnt_orph);
}

int main(int argc, char *argv[])
{
	FILE *fp;
	int res = 0;

	if (argc < 2) {
		fprintf(stderr, "Registry file not specified, exit.\n");
		return EXIT_FAILURE;
	}

	rbtree_init(&st.cells);

	st.icd = iconv_open("WCHAR_T", "UTF-16");
	if (st.icd == (iconv_t)-1) {
		fprintf(stderr, "Could not create iconv descriptor to convert UTF-16BE to WCHAR_T\n");
		return EXIT_FAILURE;
	}

	setlocale(LC_CTYPE, "");

	fp = fopen(argv[1], "rb");
	if (!fp) {
		fprintf(stderr, "Could not open registry file %s: %s\n", argv[1], strerror(errno));
		return EXIT_FAILURE;
	}

	res = regf_parse_fheader(fp);
	if (res) {
		fprintf(stderr, "Could not parse file header!\n");
		goto exit;
	}

	st.__data = mmap(NULL, st.data_sz, PROT_READ, MAP_SHARED, fileno(fp),
			 0x1000);
	if (st.__data == MAP_FAILED) {
		fprintf(stderr, "Could mmap hbin data: %s\n",
			strerror(errno));
		goto exit;
	}
	st.data = st.__data;

	res = regf_scan_data(st.data, st.data_sz);
	if (res) {
		fprintf(stderr, "Could not scan hbin data\n");
		goto exit;
	}

	res = regf_parse_root();
	if (res)
		PR_WARN(st.root_off, "root", "tree contains errors\n");

	regf_cells_stat();

exit:
	if (st.data != NULL)
		munmap(st.__data, st.data_sz);

	fclose(fp);

	return res ? EXIT_FAILURE : EXIT_SUCCESS;
}

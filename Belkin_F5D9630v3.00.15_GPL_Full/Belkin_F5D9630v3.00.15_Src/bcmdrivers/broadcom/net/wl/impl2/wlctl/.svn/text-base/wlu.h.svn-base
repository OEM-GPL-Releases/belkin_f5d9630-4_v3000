/*
 * Common code for wl command line utility
 *
 * Copyright 2002, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied or
 * duplicated in any form, in whole or in part, without the prior written
 * permission of Broadcom Corporation.
 *
 * $Id$
 */

#ifndef _wlu_h_
#define _wlu_h_

#include "wlu_cmd.h"

extern const char *av0;

/* integer output format */
extern uint8 int_fmt;

/* parse common option */
extern int wl_option(char ***pargv, char **pifname, int *phelp);
extern void wl_cmd_init(void);

/* print usage */
extern void cmd_usage(FILE *fid, cmd_t *cmd);
extern void wl_usage(FILE *fid, cmd_t *port_cmds);
extern void wl_cmds_usage(FILE *fid, cmd_t *port_cmds);

/* print helpers */
extern void wl_printlasterror(void *wl);
extern void wl_printint(int val);

/* pretty print an SSID */
extern int wl_format_ssid(char* buf, uint8* ssid, int ssid_len);

/* pretty hex print a contiguous buffer */
extern void wl_hexdump(uchar *buf, uint nbytes);

/* check driver version */
extern int wl_check(void *wl);

/* wl functions used by the ndis wl. */
extern void dump_rateset(uint8 *rates, uint count);
extern uint freq2channel(uint freq);
extern int wl_ether_atoe(const char *a, struct ether_addr *n);
extern char * wl_ether_etoa(const struct ether_addr *n);
extern cmd_func_t wl_int;
extern cmd_func_t wl_varint;
extern void wl_dump_raw_ie(bcm_tlv_t *ie, uint len);

extern void wl_printlasterror(void *wl);
extern bool wc_cmd_check(const char *cmd);

/* useful macros */
#define ARRAYSIZE(a)  (sizeof(a)/sizeof(a[0]))
/* buffer length needed for wl_format_ssid
 * 32 SSID chars, max of 4 chars for each SSID char "\xFF", plus NULL
 */
#define SSID_FMT_BUF_LEN 4*32+1	/* Length for SSID format string */

#define USAGE_ERROR  -1		/* Error code for Usage */
#define IOCTL_ERROR  -2		/* Error code for Ioctl failure */

/* integer output format */
#define INT_FMT_DEC	0	/* signed integer */
#define INT_FMT_UINT	1	/* unsigned integer */
#define INT_FMT_HEX	2	/* hexdecimal */

/* command line argument usage */
#define CMD_ERR	-1	/* Error for command */
#define CMD_OPT	0	/* a command line option */
#define CMD_WL	1	/* the start of a wl command */

#endif /* _wlu_h_ */

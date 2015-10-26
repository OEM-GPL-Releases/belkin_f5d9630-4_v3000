/*
 * Command structure for wl command line utility
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

#ifndef _wlu_cmd_h_
#define _wlu_cmd_h_

typedef struct cmd cmd_t;
typedef int (cmd_func_t)(void *wl, cmd_t *cmd, char **argv);

/* generic command line argument handler */
struct cmd {
	const char *name;
	cmd_func_t *func;
	int get;
	int set;
	const char *help;
};

/* list of command line arguments */
extern cmd_t wl_cmds[];
extern cmd_t wl_varcmd;

/* per-port ioctl handlers */
extern int wl_get(void *wl, int cmd, void *buf, int len);
extern int wl_set(void *wl, int cmd, void *buf, int len);

#endif /* _wlu_cmd_h_ */

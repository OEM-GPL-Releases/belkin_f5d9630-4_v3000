/*
 * wl_linux.c exported functions and definitions
 *
 * Copyright 2006, Broadcom Corporation
 * All Rights Reserved.                
 *                                     
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;   
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior      
 * written permission of Broadcom Corporation.                            
 *
 * $Id$
 */

#ifndef _wl_linux_h_
#define _wl_linux_h_
/* handle forward declaration */
typedef struct wl_info wl_info_t;

/* exported functions */
extern int __devinit wl_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
extern irqreturn_t   wl_isr(int irq, void *dev_id, struct pt_regs *ptregs);
extern void wl_free(wl_info_t *wl);
extern int  wl_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
extern struct net_device * wl_netdev_get(wl_info_t *wl);
#ifdef DSLCPE
extern void wl_shutdown_handler(wl_info_t *wl);
extern int wl_suspend(struct pci_dev *pdev, u32 state);
extern void wl_reset_cnt(struct net_device *dev);
#endif /* DSLCPE */
#ifdef BCM_WL_EMULATOR
extern wl_info_t *  wl_wlcreate(osl_t *osh, void *pdev);
#endif /* BCM_WL_EMULATOR */
#endif /* _wl_linux_h_ */

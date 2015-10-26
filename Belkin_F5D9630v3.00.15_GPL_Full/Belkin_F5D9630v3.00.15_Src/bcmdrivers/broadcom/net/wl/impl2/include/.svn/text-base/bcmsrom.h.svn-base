/*
 * Misc useful routines to access NIC local SROM/OTP .
 *
 * Copyright 2006, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 * $Id$
 */

#ifndef	_bcmsrom_h_
#define	_bcmsrom_h_

/* Maximum srom: 4 Kilobits == 512 bytes */
#define	SROM_MAX		512


#define	SROM_WORDS		64

#define	SROM_WL1LHMAXP		29

#define	SROM_WL1LPAB0		30
#define	SROM_WL1LPAB1		31
#define	SROM_WL1LPAB2		32

#define	SROM_WL1HPAB0		33
#define	SROM_WL1HPAB1		34
#define	SROM_WL1HPAB2		35

#define	SROM_MACHI_IL0		36
#define	SROM_MACMID_IL0		37
#define	SROM_MACLO_IL0		38
#define	SROM_MACHI_ET0		39
#define	SROM_MACMID_ET0		40
#define	SROM_MACLO_ET0		41
#define	SROM_MACHI_ET1		42
#define	SROM_MACMID_ET1		43
#define	SROM_MACLO_ET1		44
#define	SROM3_MACHI		37
#define	SROM3_MACMID		38
#define	SROM3_MACLO		39

#define	SROM_BXARSSI2G		40
#define	SROM_BXARSSI5G		41

#define	SROM_TRI52G		42
#define	SROM_TRI5GHL		43

#define	SROM_RXPO52G		45

#define	SROM2_ENETPHY		45

#define	SROM_AABREV		46

#define	SROM_WL0PAB0		47
#define	SROM_WL0PAB1		48
#define	SROM_WL0PAB2		49

#define	SROM_LEDBH10		50
#define	SROM_LEDBH32		51

#define	SROM_WL10MAXP		52

#define	SROM_WL1PAB0		53
#define	SROM_WL1PAB1		54
#define	SROM_WL1PAB2		55

#define	SROM_ITT		56

#define	SROM_BFL		57
#define	SROM_BFL2		28
#define	SROM3_BFL2		61

#define	SROM_AG10		58

#define	SROM_CCODE		59

#define	SROM_OPO		60

#define	SROM3_LEDDC		62

#define	SROM_CRCREV		63

/* SROM Rev 4: Reallocate the software part of the srom to accomodate
 * MIMO features. It assumes up to two PCIE functions and 440 bytes
 * of useable srom i.e. the useable storage in chips with OTP that
 * implements hardware redundancy.
 */

#define	SROM4_WORDS		220

#define	SROM4_SIGN		32
#define	SROM4_SIGNATURE		0x5372

#define	SROM4_BREV		33

#define	SROM4_BFL0		34
#define	SROM4_BFL1		35
#define	SROM4_BFL2		36
#define	SROM4_BFL3		37
#define	SROM5_BFL0		37
#define	SROM5_BFL1		38
#define	SROM5_BFL2		39
#define	SROM5_BFL3		40

#define	SROM4_MACHI		38
#define	SROM4_MACMID		39
#define	SROM4_MACLO		40
#define	SROM5_MACHI		41
#define	SROM5_MACMID		42
#define	SROM5_MACLO		43

#define	SROM4_CCODE		41
#define	SROM4_REGREV		42
#define	SROM5_CCODE		34
#define	SROM5_REGREV		35

#define	SROM4_LEDBH10		43
#define	SROM4_LEDBH32		44
#define	SROM5_LEDBH10		59
#define	SROM5_LEDBH32		60

#define	SROM4_LEDDC		45

#define	SROM4_AA		46
#define	SROM4_AA2G_MASK		0x00ff
#define	SROM4_AA2G_SHIFT	0
#define	SROM4_AA5G_MASK		0xff00
#define	SROM4_AA5G_SHIFT	8

#define	SROM4_AG10		47
#define	SROM4_AG32		48

#define	SROM4_TXPID2G		49
#define	SROM4_TXPID5G		51
#define	SROM4_TXPID5GL		53
#define	SROM4_TXPID5GH		55

#define SROM4_TXRXC		61
#define SROM4_TXCHAIN_MASK	0x000f
#define SROM4_TXCHAIN_SHIFT	0
#define SROM4_RXCHAIN_MASK	0x00f0
#define SROM4_RXCHAIN_SHIFT	4
#define SROM4_SWITCH_MASK	0xff00
#define SROM4_SWITCH_SHIFT	8

/* Per-path fields */
#define	MAX_PATH		4
#define	SROM4_PATH0		64
#define	SROM4_PATH1		87
#define	SROM4_PATH2		110
#define	SROM4_PATH3		133

#define	SROM4_2G_ITT_MAXP	0
#define	SROM4_2G_PA		1
#define	SROM4_5G_ITT_MAXP	5
#define	SROM4_5GLH_MAXP		6
#define	SROM4_5G_PA		7
#define	SROM4_5GL_PA		11
#define	SROM4_5GH_PA		15

/* Fields in the ITT_MAXP and 5GLH_MAXP words */
#define	B2G_MAXP_MASK		0xff
#define	B2G_ITT_SHIFT		8
#define	B5G_MAXP_MASK		0xff
#define	B5G_ITT_SHIFT		8
#define	B5GH_MAXP_MASK		0xff
#define	B5GL_MAXP_SHIFT		8

/* All the miriad power offsets */
#define	SROM4_2G_CCKPO		156
#define	SROM4_2G_OFDMPO		157
#define	SROM4_5G_OFDMPO		159
#define	SROM4_5GL_OFDMPO	161
#define	SROM4_5GH_OFDMPO	163
#define	SROM4_2G_MCSPO		165
#define	SROM4_5G_MCSPO		173
#define	SROM4_5GL_MCSPO		181
#define	SROM4_5GH_MCSPO		189
#define	SROM4_CDDPO		197
#define	SROM4_STBCPO		198
#define	SROM4_BW40PO		199
#define	SROM4_BWDUPPO		200

#define	SROM4_CRCREV		219

extern int srom_var_init(void *sbh, uint bus, void *curmap, osl_t *osh, char **vars, uint *count);

extern int srom_read(uint bus, void *curmap, osl_t *osh, uint byteoff, uint nbytes, uint16 *buf);
extern int srom_write(uint bus, void *curmap, osl_t *osh, uint byteoff, uint nbytes, uint16 *buf);

extern int srom_parsecis(osl_t *osh, uint8 **pcis, uint ciscnt, char **vars, uint *count);

#ifdef	SB_PCMCIA_SROM

extern int get_sb_pcmcia_srom(osl_t *osh, uint8 *pcmregs, uint16 *srom, uint size);

#endif	/* SB_PCMCIA_SROM */

#endif	/* _bcmsrom_h_ */

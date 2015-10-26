/*
 *  Misc useful routines to access NIC SROM/OTP .
 *
 * Copyright 2006, Broadcom Corporation
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 * $Id$
 */

#include <typedefs.h>
#include <bcmdefs.h>
#include <osl.h>
#include <bcmutils.h>
#include <bcmsrom.h>
#include <bcmdevs.h>
#include <bcmendian.h>
#include <sbpcmcia.h>
#include <pcicfg.h>
#include <sbconfig.h>
#include <sbutils.h>
#include <bcmnvram.h>

#ifndef DSLCPE
#ifdef WLTEST
#include <sbsprom.h>
#endif /* WLTEST */
#endif /* DSLCPE */

#include <proto/ethernet.h>	/* for sprom content groking */
#if defined(DSLCPE) && defined(DSLCPE_WOMBO)
extern int read_sromfile(void *buf, uint offset, uint nbytes);
#endif

/* debug/trace */
#if defined(BCMDBG_ERR) || defined(WLTEST)
#define	BS_ERROR(args)	printf args
#else
#define	BS_ERROR(args)
#endif	/* BCMDBG_ERR || WLTEST */

#define	VARS_MAX	4096	/* should be reduced */

#define WRITE_ENABLE_DELAY	500	/* 500 ms after write enable/disable toggle */
#define WRITE_WORD_DELAY	20	/* 20 ms between each word write */

static int initvars_srom_pci(void *sbh, void *curmap, char **vars, uint *count);
static int initvars_cis_pcmcia(void *sbh, osl_t *osh, char **vars, uint *count);
static int initvars_flash_sb(void *sbh, char **vars, uint *count);
static int sprom_cmd_pcmcia(osl_t *osh, uint8 cmd);
static int sprom_read_pcmcia(osl_t *osh, uint16 addr, uint16 *data);
static int sprom_write_pcmcia(osl_t *osh, uint16 addr, uint16 data);
static int sprom_read_pci(osl_t *osh, uint16 *sprom, uint wordoff, uint16 *buf, uint nwords,
                          bool check_crc);

static int initvars_table(osl_t *osh, char *start, char *end, char **vars, uint *count);
static int initvars_flash(osl_t *osh, char **vp, uint len, char *devpath);

#if defined(DSLCPE) && defined(DSLCPE_WOMBO)
char wl_srom_present = 1; /* default is present, only wombo board don't have srom */

#define SROM_SCANAREA 12
int wl_probe_srom(osl_t *osh, void *curmap)
{
	int i;
	uint16 tmp;
	uint16 *srom;

	if (!curmap) {
		return 1;
	}
	srom = (uint16 *)((uint)curmap + PCI_BAR0_SPROM_OFFSET);

	for (i = 0; i < SROM_SCANAREA; i++) {
		tmp = R_REG(osh, &srom[i]);
		if (tmp != 0x0000 && tmp !=0xffff) {
			return 1; /* assuming srom is present */
		}
	}
	return 0;
}
#endif
/*
 * Initialize local vars from the right source for this platform.
 * Return 0 on success, nonzero on error.
 */
int
BCMINITFN(srom_var_init)(void *sbh, uint bustype, void *curmap, osl_t *osh,
	char **vars, uint *count)
{
	ASSERT(bustype == BUSTYPE(bustype));
	if (vars == NULL || count == NULL)
		return (0);

	switch (BUSTYPE(bustype)) {
	case SB_BUS:
	case JTAG_BUS:
		return initvars_flash_sb(sbh, vars, count);

	case PCI_BUS:
		ASSERT(curmap);	/* can not be NULL */
		return initvars_srom_pci(sbh, curmap, vars, count);

	case PCMCIA_BUS:
		return initvars_cis_pcmcia(sbh, osh, vars, count);


	default:
		ASSERT(0);
	}
	return (-1);
}

/* support only 16-bit word read from srom */
int
srom_read(uint bustype, void *curmap, osl_t *osh, uint byteoff, uint nbytes, uint16 *buf)
{
	void *srom;
	uint i, off, nw;

	ASSERT(bustype == BUSTYPE(bustype));

	/* check input - 16-bit access only */
	if (byteoff & 1 || nbytes & 1 || (byteoff + nbytes) > (SPROM_SIZE * 2))
		return 1;

	off = byteoff / 2;
	nw = nbytes / 2;

	if (BUSTYPE(bustype) == PCI_BUS) {
		if (!curmap)
			return 1;
		srom = (uchar*)curmap + PCI_BAR0_SPROM_OFFSET;
		if (sprom_read_pci(osh, srom, off, buf, nw, FALSE))
			return 1;
	} else if (BUSTYPE(bustype) == PCMCIA_BUS) {
		for (i = 0; i < nw; i++) {
			if (sprom_read_pcmcia(osh, (uint16)(off + i), (uint16 *)(buf + i)))
				return 1;
		}
	} else {
		return 1;
	}

	return 0;
}

/* support only 16-bit word write into srom */
int
srom_write(uint bustype, void *curmap, osl_t *osh, uint byteoff, uint nbytes, uint16 *buf)
{
	uint16 *srom;
	uint i, nw, crc_range;
	uint16 image[SPROM_SIZE];
	uint8 crc;
	volatile uint32 val32;

	ASSERT(bustype == BUSTYPE(bustype));

	/* check input - 16-bit access only */
	if ((byteoff & 1) || (nbytes & 1))
		return 1;

	if (byteoff == 0x55aa) {
		/* Erase request */
		crc_range = 0;
		memset((void *)image, 0xff, nbytes);
		nw = nbytes / 2;
	} else if ((byteoff == 0) &&
	           ((nbytes == SPROM_SIZE) ||
	            (nbytes == (SPROM_CRC_RANGE * 2)) ||
	            (nbytes == (SROM4_WORDS * 2)))) {
		/* Are we writing the whole thing at once? */
		crc_range = nbytes;
		bcopy((void *)buf, (void *)image, nbytes);
		nw = nbytes / 2;
	} else {
		if ((byteoff + nbytes) > (SPROM_SIZE * 2))
			return 1;

		if ((BUSTYPE(bustype) == PCMCIA_BUS) || (BUSTYPE(bustype) == SDIO_BUS))
			crc_range = SPROM_SIZE;
		else
			crc_range = SPROM_CRC_RANGE * 2;	/* Tentative */

		nw = crc_range / 2;
		/* read first 64 words from srom */
		if (srom_read(bustype, curmap, osh, 0, crc_range, image))
			return 1;
		if (image[SROM4_SIGN] == SROM4_SIGNATURE) {
			nw = SROM4_WORDS;
			crc_range = nw * 2;
			if (srom_read(bustype, curmap, osh, 0, crc_range, image))
				return 1;
		}
		/* make changes */
		bcopy((void *)buf, (void *)&image[byteoff / 2], nbytes);
	}

	if (crc_range) {
		/* calculate crc */
		htol16_buf(image, crc_range);
		crc = ~hndcrc8((uint8 *)image, crc_range - 1, CRC8_INIT_VALUE);
		ltoh16_buf(image, crc_range);
		image[nw - 1] = (crc << 8) | (image[nw - 1] & 0xff);
	}

	if (BUSTYPE(bustype) == PCI_BUS) {
#if defined(DSLCPE) && defined(DSLCPE_WOMBO)
		if (wl_srom_present == 0) {
			printk("wl: write to main memory mapped srom not supported\n");			
		} else {
		
#endif		
		srom = (uint16 *)((uchar*)curmap + PCI_BAR0_SPROM_OFFSET);
		/* enable writes to the SPROM */
		val32 = OSL_PCI_READ_CONFIG(osh, PCI_SPROM_CONTROL, sizeof(uint32));
		val32 |= SPROM_WRITEEN;
		OSL_PCI_WRITE_CONFIG(osh, PCI_SPROM_CONTROL, sizeof(uint32), val32);
		bcm_mdelay(WRITE_ENABLE_DELAY);
		/* write srom */
		for (i = 0; i < nw; i++) {
			W_REG(osh, &srom[i], image[i]);
			bcm_mdelay(WRITE_WORD_DELAY);
		}
		/* disable writes to the SPROM */
		OSL_PCI_WRITE_CONFIG(osh, PCI_SPROM_CONTROL, sizeof(uint32), val32 &
		                     ~SPROM_WRITEEN);
#if defined(DSLCPE) && defined(DSLCPE_WOMBO)
		}
#endif		
	} else if (BUSTYPE(bustype) == PCMCIA_BUS) {
		/* enable writes to the SPROM */
		if (sprom_cmd_pcmcia(osh, SROM_WEN))
			return 1;
		bcm_mdelay(WRITE_ENABLE_DELAY);
		/* write srom */
		for (i = 0; i < nw; i++) {
			sprom_write_pcmcia(osh, (uint16)(i), image[i]);
			bcm_mdelay(WRITE_WORD_DELAY);
		}
		/* disable writes to the SPROM */
		if (sprom_cmd_pcmcia(osh, SROM_WDS))
			return 1;
	} else {
		return 1;
	}

	bcm_mdelay(WRITE_ENABLE_DELAY);
	return 0;
}

#ifdef	SB_PCMCIA_SROM

#define	SB_PCMCIA_READ(regs, fcr) *((volatile uint8 *)((regs) + 0x600 + fcr - (0x700 / 2)))
#define	SB_PCMCIA_WRITE(regs, fcr, v) \
		*((volatile uint8 *)((regs) + 0x600 + (((fcr * 2) - 0x700) / 2))) = (v)

uint max_wait_cnt = 0;

/* set PCMCIA srom command register */
static int
srom_cmd_sb_pcmcia(uint8 *pcmregs, uint8 cmd)
{
	uint8 status = 0;
	uint wait_cnt = 0;

	/* write srom command register */
	SB_PCMCIA_WRITE(pcmregs, SROM_CS, cmd);

	/* wait status */
	while (++wait_cnt < 1000000) {
		status = SB_PCMCIA_READ(pcmregs, SROM_CS);
		if (status & SROM_DONE) {
			if (wait_cnt > max_wait_cnt)
				max_wait_cnt = wait_cnt;
			return 0;
		}
	}
	BS_ERROR(("sr_cmd: Give up after %d tries, stat = 0x%x\n", wait_cnt, status));
	return 1;
}

/* read a word from the PCMCIA srom over SB */
static int
srom_read_sb_pcmcia(uint8 *pcmregs, uint16 addr, uint16 *data)
{
	uint8 addr_l, addr_h,  data_l, data_h;

	addr_l = (uint8)((addr * 2) & 0xff);
	addr_h = (uint8)(((addr * 2) >> 8) & 0xff);

	/* set address */
	SB_PCMCIA_WRITE(pcmregs, SROM_ADDRH, addr_h);
	SB_PCMCIA_WRITE(pcmregs, SROM_ADDRL, addr_l);

	/* do read */
	if (srom_cmd_sb_pcmcia(pcmregs, SROM_READ))
		return 1;

	/* read data */
	data_h = SB_PCMCIA_READ(pcmregs, SROM_DATAH);
	data_l = SB_PCMCIA_READ(pcmregs, SROM_DATAL);
	*data = ((uint16)data_h << 8) | data_l;

	return 0;
}

#ifdef	notyet

/* write a word to the PCMCIA srom */
static int
srom_write_sb_pcmcia(uint8 *pcmregs, uint16 addr, uint16 data)
{
	uint8 addr_l, addr_h, data_l, data_h;

	addr_l = (uint8)((addr * 2) & 0xff);
	addr_h = (uint8)(((addr * 2) >> 8) & 0xff);
	data_l = (uint8)(data & 0xff);
	data_h = (uint8)((data >> 8) & 0xff);

	/* set address */
	SB_PCMCIA_WRITE(pcmregs, SROM_ADDRH, addr_h);
	SB_PCMCIA_WRITE(pcmregs, SROM_ADDRL, addr_l);

	/* write data */
	SB_PCMCIA_WRITE(pcmregs, SROM_DATAH, data_h);
	SB_PCMCIA_WRITE(pcmregs, SROM_DATAL, data_l);

	/* do write */
	return srom_cmd_sb_pcmcia(pcmregs, SROM_WRITE);
}
#endif	/* notyet */


/*
 * Read the srom for the pcmcia-srom over sb case.
 * Return 0 on success, nonzero on error.
 */
int
get_sb_pcmcia_srom(osl_t *osh, uint8 *pcmregs, uint16 *srom, uint size)
{
	uint8 crc;
	int rc = 0;
	uint i, nb, nw;


	if ((SB_PCMCIA_READ(pcmregs, SROM_INFO) & SRI_SZ_MASK) != 1)
		return -1;

	nw = 256;	/* SROM_INFO == 1 means 4Kbit i.e. 512 bytes, 256 words */
	nb = 2 * nw;

	if (size < nb)
		return -2;

	for (i = 0; i < nw; i++)
		if (srom_read_sb_pcmcia(pcmregs, i, &srom[i])) {
			rc = -3;
			goto out;
		}

	crc = hndcrc8((uint8 *)srom, nw * 2, CRC8_INIT_VALUE);
	if (crc != CRC8_GOOD_VALUE) {
		rc = -4;
		goto out;
	}

out:

	return (rc);
}
#endif	/* SB_PCMCIA_SROM */

int
srom_parsecis(osl_t *osh, uint8 **pcis, uint ciscnt, char **vars, uint *count)
{
	char eabuf[32];
	char *vp, *base;
	uint8 *cis, tup, tlen, sromrev = 1;
	int i, j;
	uint varsize;
	bool ag_init = FALSE;
	uint32 w32;
	uint funcid;
	uint cisnum;

	ASSERT(vars);
	ASSERT(count);

	base = vp = MALLOC(osh, VARS_MAX);
	ASSERT(vp);
	if (!vp)
		return -2;

	for (cisnum = 0; cisnum < ciscnt; cisnum++) {
		cis = *pcis++;
		i = 0;
		funcid = 0;
		do {
			tup = cis[i++];
			tlen = cis[i++];
			if ((i + tlen) >= CIS_SIZE)
				break;

			switch (tup) {
			case CISTPL_VERS_1:
				/* assume the strings are good if the version field checks out */
				if (((cis[i + 1] << 8) + cis[i]) >= 0x0008) {
					vp += sprintf(vp, "manf=%s", &cis[i + 2]);
					vp++;
					vp += sprintf(vp, "productname=%s",
					              &cis[i + 3 + strlen((char *)&cis[i + 2])]);
					vp++;
					break;
				}

			case CISTPL_MANFID:
				vp += sprintf(vp, "manfid=%d", (cis[i + 1] << 8) + cis[i]);
				vp++;
				vp += sprintf(vp, "prodid=%d", (cis[i + 3] << 8) + cis[i + 2]);
				vp++;
				break;

			case CISTPL_FUNCID:
				funcid = cis[i];
				break;

			case CISTPL_FUNCE:
				switch (funcid) {
				default:
					if (cis[i] == LAN_NID) {
						ASSERT(cis[i + 1] == ETHER_ADDR_LEN);
						vp += sprintf(vp, "boardnum=%d",
						              (cis[i + 6] << 8) + cis[i + 7]);
						vp++;
						bcm_ether_ntoa((struct ether_addr *)&cis[i + 2],
						               eabuf);
						vp += sprintf(vp, "macaddr=%s", eabuf);
						vp++;
						break;
					}
					break;
				}
				break;

			case CISTPL_CFTABLE:
				vp += sprintf(vp, "regwindowsz=%d", (cis[i + 7] << 8) | cis[i + 6]);
				vp++;
				break;

			case CISTPL_BRCM_HNBU:
				switch (cis[i]) {
				case HNBU_SROMREV:
					sromrev = cis[i + 1];
					break;

				case HNBU_CHIPID:
					vp += sprintf(vp, "vendid=%d", (cis[i + 2] << 8) +
					              cis[i + 1]);
					vp++;
					vp += sprintf(vp, "devid=%d", (cis[i + 4] << 8) +
					              cis[i + 3]);
					vp++;
					if (tlen == 7) {
						vp += sprintf(vp, "chiprev=%d",
						              (cis[i + 6] << 8) + cis[i + 5]);
						vp++;
					}
					break;

				case HNBU_BOARDREV:
					vp += sprintf(vp, "boardrev=%d", cis[i + 1]);
					vp++;
					break;

				case HNBU_AA:
					vp += sprintf(vp, "aa2g=%d", cis[i + 1]);
					vp++;
					break;

				case HNBU_AG:
					vp += sprintf(vp, "ag0=%d", cis[i + 1]);
					vp++;
					ag_init = TRUE;
					break;

				case HNBU_ANT5G:
					vp += sprintf(vp, "aa5g=%d", cis[i + 1]);
					vp++;
					vp += sprintf(vp, "ag1=%d", cis[i + 2]);
					vp++;
					break;

				case HNBU_CC:
					ASSERT(sromrev == 1);
					vp += sprintf(vp, "cc=%d", cis[i + 1]);
					vp++;
					break;

				case HNBU_PAPARMS:
					if (tlen == 2) {
						ASSERT(sromrev == 1);
						vp += sprintf(vp, "pa0maxpwr=%d", cis[i + 1]);
						vp++;
					} else if (tlen >= 9) {
						if (tlen == 10) {
							ASSERT(sromrev == 2);
							vp += sprintf(vp, "opo=%d", cis[i + 9]);
							vp++;
						} else
							ASSERT(tlen == 9);

						for (j = 0; j < 3; j++) {
							vp += sprintf(vp, "pa0b%d=%d", j,
							              (cis[i + (j * 2) + 2] << 8) +
							              cis[i + (j * 2) + 1]);
							vp++;
						}
						vp += sprintf(vp, "pa0itssit=%d", cis[i + 7]);
						vp++;
						vp += sprintf(vp, "pa0maxpwr=%d", cis[i + 8]);
						vp++;
					} else
						ASSERT(tlen >= 9);
					break;

				case HNBU_OEM:
					ASSERT(sromrev == 1);
					vp += sprintf(vp, "oem=%02x%02x%02x%02x%02x%02x%02x%02x",
					              cis[i + 1], cis[i + 2],
					              cis[i + 3], cis[i + 4],
					              cis[i + 5], cis[i + 6],
					              cis[i + 7], cis[i + 8]);
					vp++;
					break;

				case HNBU_BOARDFLAGS:
					w32 = (cis[i + 2] << 8) + cis[i + 1];
					if (tlen == 5)
						w32 |= (cis[i + 4] << 24) + (cis[i + 3] << 16);
					vp += sprintf(vp, "boardflags=0x%x", w32);
					vp++;
					break;

				case HNBU_LEDS:
					if (cis[i + 1] != 0xff) {
						vp += sprintf(vp, "ledbh0=%d", cis[i + 1]);
						vp++;
					}
					if (cis[i + 2] != 0xff) {
						vp += sprintf(vp, "ledbh1=%d", cis[i + 2]);
						vp++;
					}
					if (cis[i + 3] != 0xff) {
						vp += sprintf(vp, "ledbh2=%d", cis[i + 3]);
						vp++;
					}
					if (cis[i + 4] != 0xff) {
						vp += sprintf(vp, "ledbh3=%d", cis[i + 4]);
						vp++;
					}
					break;

				case HNBU_CCODE:
				{
					ASSERT(sromrev > 1);
					if ((cis[i + 1] == 0) || (cis[i + 2] == 0))
						vp += sprintf(vp, "ccode=");
					else
						vp += sprintf(vp, "ccode=%c%c",
						              cis[i + 1], cis[i + 2]);
					vp++;
					vp += sprintf(vp, "cctl=0x%x", cis[i + 3]);
					vp++;
					break;
				}

				case HNBU_CCKPO:
					ASSERT(sromrev > 2);
					vp += sprintf(vp, "cckpo=0x%x",
					              (cis[i + 2] << 8) | cis[i + 1]);
					vp++;
					break;

				case HNBU_OFDMPO:
					ASSERT(sromrev > 2);
					vp += sprintf(vp, "ofdmpo=0x%x",
					              (cis[i + 4] << 24) |
					              (cis[i + 3] << 16) |
					              (cis[i + 2] << 8) |
					              cis[i + 1]);
					vp++;
					break;

				case HNBU_RDLID:
					vp += sprintf(vp, "rdlid=0x%x",
					              (cis[i + 2] << 8) | cis[i + 1]);
					vp++;
					break;

				case HNBU_RDLRNDIS:
					vp += sprintf(vp, "rdlrndis=%d", cis[i + 1]);
					vp++;
					break;

				case HNBU_RDLRWU:
					vp += sprintf(vp, "rdlrwu=%d", cis[i + 1]);
					vp++;
					break;

				case HNBU_XTALFREQ:
					vp += sprintf(vp, "xtalfreq=%d",
					              (cis[i + 4] << 24) |
					              (cis[i + 3] << 16) |
					              (cis[i + 2] << 8) |
					              cis[i + 1]);
					vp++;
					break;
				}
				break;
			}
			i += tlen;
		} while (tup != 0xff);
	}

	/* Set the srom version */
	vp += sprintf(vp, "sromrev=%d", sromrev);
	vp++;

	/* if there is no antenna gain field, set default */
	if (ag_init == FALSE) {
		vp += sprintf(vp, "ag0=%d", 0xff);
		vp++;
	}

	/* final nullbyte terminator */
	*vp++ = '\0';
	varsize = (uint)(vp - base);

	ASSERT((vp - base) < VARS_MAX);

	if (varsize == VARS_MAX) {
		*vars = base;
	} else {
		vp = MALLOC(osh, varsize);
		ASSERT(vp);
		if (vp)
			bcopy(base, vp, varsize);
		MFREE(osh, base, VARS_MAX);
		*vars = vp;
		if (!vp) {
			*count = 0;
			return -2;
		}
	}
	*count = varsize;

	return (0);
}


/* set PCMCIA sprom command register */
static int
sprom_cmd_pcmcia(osl_t *osh, uint8 cmd)
{
	uint8 status = 0;
	uint wait_cnt = 1000;

	/* write sprom command register */
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_CS, &cmd, 1);

	/* wait status */
	while (wait_cnt--) {
		OSL_PCMCIA_READ_ATTR(osh, SROM_CS, &status, 1);
		if (status & SROM_DONE)
			return 0;
	}

	return 1;
}

/* read a word from the PCMCIA srom */
static int
sprom_read_pcmcia(osl_t *osh, uint16 addr, uint16 *data)
{
	uint8 addr_l, addr_h, data_l, data_h;

	addr_l = (uint8)((addr * 2) & 0xff);
	addr_h = (uint8)(((addr * 2) >> 8) & 0xff);

	/* set address */
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_ADDRH, &addr_h, 1);
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_ADDRL, &addr_l, 1);

	/* do read */
	if (sprom_cmd_pcmcia(osh, SROM_READ))
		return 1;

	/* read data */
	data_h = data_l = 0;
	OSL_PCMCIA_READ_ATTR(osh, SROM_DATAH, &data_h, 1);
	OSL_PCMCIA_READ_ATTR(osh, SROM_DATAL, &data_l, 1);

	*data = (data_h << 8) | data_l;
	return 0;
}

/* write a word to the PCMCIA srom */
static int
sprom_write_pcmcia(osl_t *osh, uint16 addr, uint16 data)
{
	uint8 addr_l, addr_h, data_l, data_h;

	addr_l = (uint8)((addr * 2) & 0xff);
	addr_h = (uint8)(((addr * 2) >> 8) & 0xff);
	data_l = (uint8)(data & 0xff);
	data_h = (uint8)((data >> 8) & 0xff);

	/* set address */
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_ADDRH, &addr_h, 1);
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_ADDRL, &addr_l, 1);

	/* write data */
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_DATAH, &data_h, 1);
	OSL_PCMCIA_WRITE_ATTR(osh, SROM_DATAL, &data_l, 1);

	/* do write */
	return sprom_cmd_pcmcia(osh, SROM_WRITE);
}

/*
 * Read in and validate sprom.
 * Return 0 on success, nonzero on error.
 */
static int
sprom_read_pci(osl_t *osh, uint16 *sprom, uint wordoff, uint16 *buf, uint nwords, bool check_crc)
{
	int err = 0;
	uint i;

#if defined(DSLCPE) && defined(DSLCPE_WOMBO)
	if (wl_srom_present == 0) {
		int bytes_read;
		/* no srom, use memory map */
		read_sromfile(buf, wordoff*2, nwords*2);

		if(check_crc) {
			/* hack to work with rev4 srom on wombo*/
			bytes_read = read_sromfile(buf, 0, SROM4_WORDS*2);
			if ((bytes_read == SROM4_WORDS*2) && (SROM4_WORDS > nwords)) {
				/* not reading enough */
				err = 1;
			}						
		}
		return err;		
	}	
#endif

	/* read the sprom */
	for (i = 0; i < nwords; i++) {
#ifdef BCMQT
		buf[i] = R_REG(osh, &sprom[wordoff + i]);
#endif
		buf[i] = R_REG(osh, &sprom[wordoff + i]);
	}

	if (check_crc) {
		if (buf[0] == 0xffff) {
			/* The hardware thinks that an srom that starts with 0xffff
			 * is blank, regardless of the rest of the content, so declare
			 * it bad.
			 */
			BS_ERROR(("%s: buf[0] = 0x%x, returning bad-crc\n", __FUNCTION__, buf[0]));
			return 1;
		}

		/* fixup the endianness so crc8 will pass */
		htol16_buf(buf, nwords * 2);
		if (hndcrc8((uint8 *)buf, nwords * 2, CRC8_INIT_VALUE) != CRC8_GOOD_VALUE)
			err = 1;
		/* now correct the endianness of the byte array */
		ltoh16_buf(buf, nwords * 2);
	}

	return err;
}

/*
* Create variable table from memory.
* Return 0 on success, nonzero on error.
*/
static int
BCMINITFN(initvars_table)(osl_t *osh, char *start, char *end, char **vars, uint *count)
{
	int c = (int)(end - start);

	/* do it only when there is more than just the null string */
	if (c > 1) {
		char *vp = MALLOC(osh, c);
		ASSERT(vp);
		if (!vp)
			return BCME_NOMEM;
		bcopy(start, vp, c);
		*vars = vp;
		*count = c;
	}
	else {
		*vars = NULL;
		*count = 0;
	}

	return 0;
}

/*
 * Find variables with <devpath> from flash. 'base' points to the beginning
 * of the table upon enter and to the end of the table upon exit when success.
 * Return 0 on success, nonzero on error.
 */
static int
BCMINITFN(initvars_flash)(osl_t *osh, char **base, uint len, char *devpath)
{
	char *vp = *base;
	char *flash;
	int err;
	char *s;
	uint l, dl, copy_len;

	/* allocate memory and read in flash */
	if (!(flash = MALLOC(osh, NVRAM_SPACE)))
		return BCME_NOMEM;
	if ((err = nvram_getall(flash, NVRAM_SPACE)))
		goto exit;

	/* grab vars with the <devpath> prefix in name */
	dl = strlen(devpath);
	for (s = flash; s && *s; s += l + 1) {
		l = strlen(s);

		/* skip non-matching variable */
		if (strncmp(s, devpath, dl))
			continue;

		/* is there enough room to copy? */
		copy_len = l - dl + 1;
		if (len < copy_len) {
			err = BCME_BUFTOOSHORT;
			goto exit;
		}

		/* no prefix, just the name=value */
		strcpy(vp, &s[dl]);
		vp += copy_len;
		len -= copy_len;
	}

	/* add null string as terminator */
	if (len < 1) {
		err = BCME_BUFTOOSHORT;
		goto exit;
	}
	*vp++ = '\0';

	*base = vp;

exit:	MFREE(osh, flash, NVRAM_SPACE);
	return err;
}

/*
 * Initialize nonvolatile variable table from flash.
 * Return 0 on success, nonzero on error.
 */
static int
BCMINITFN(initvars_flash_sb)(void *sbh, char **vars, uint *count)
{
	osl_t *osh = sb_osh(sbh);
	char devpath[SB_DEVPATH_BUFSZ];
	char *vp, *base;
	int err;

	ASSERT(vars);
	ASSERT(count);

	if ((err = sb_devpath(sbh, devpath, sizeof(devpath))))
		return err;

	base = vp = MALLOC(osh, VARS_MAX);
	ASSERT(vp);
	if (!vp)
		return BCME_NOMEM;

	if ((err = initvars_flash(osh, &vp, VARS_MAX, devpath)))
		goto err;

	err = initvars_table(osh, base, vp, vars, count);

err:	MFREE(osh, base, VARS_MAX);
	return err;
}

#ifdef WLTEST
char mfgsromvars[256];
char *defaultsromvars = "il0macaddr=00:11:22:33:44:51\0"
		"et0macaddr=00:11:22:33:44:52\0"
		"et1macaddr=00:11:22:33:44:53\0"
		"boardtype=0xffff\0"
		"boardrev=0x10\0"
		"boardflags=8\0"
		"sromrev=2\0"
		"aa2g=3";
#define	MFGSROM_DEFVARSLEN	147 /* default srom len */
#endif /* WL_TEST */

static int
addmacaddr(char *vp, const char *name, uint16 hi, uint16 mid, uint16 lo)
{
	struct ether_addr ea;
	char eabuf[32];

	ea.octet[0] = (hi >> 8) & 0xff;
	ea.octet[1] = hi & 0xff;
	ea.octet[2] = (mid >> 8) & 0xff;
	ea.octet[3] = mid & 0xff;
	ea.octet[4] = (lo >> 8) & 0xff;
	ea.octet[5] = lo & 0xff;
	bcm_ether_ntoa(&ea, eabuf);
	return sprintf(vp, "%s=%s", name, eabuf);
}

/*
 * Initialize nonvolatile variable table from sprom.
 * Return 0 on success, nonzero on error.
 */
static int
BCMINITFN(initvars_srom_pci)(void *sbh, void *curmap, char **vars, uint *count)
{
	uint16 w, *b;
	uint8 sromrev = 0;
	uint32 w32;
	int i;
	char *vp, *base = NULL;
	osl_t *osh = sb_osh(sbh);
	bool flash = FALSE;
	uint16 bfl2;
	char name[SB_DEVPATH_BUFSZ+16], *value;
	char devpath[SB_DEVPATH_BUFSZ];
	int err = 0;

	/*
	 * Apply CRC over SROM content regardless SROM is present or not,
	 * and use variable <devpath>sromrev's existance in flash to decide
	 * if we should return an error when CRC fails or read SROM variables
	 * from flash.
	 */
	b = MALLOC(osh, SROM_MAX);
	ASSERT(b);
	if (!b)
		return -2;

	err = sprom_read_pci(osh, (void *)((int8 *)curmap + PCI_BAR0_SPROM_OFFSET), 0, b,
	                     SROM_WORDS, TRUE);

	if (b[SROM4_SIGN] == SROM4_SIGNATURE) {
		/* sromrev >= 4, read more */
		err = sprom_read_pci(osh, (void *)((int8 *)curmap + PCI_BAR0_SPROM_OFFSET), 0, b,
		                     SROM4_WORDS, TRUE);
		sromrev = b[SROM4_CRCREV] & 0xff;
	} else if (err == 0) {
		/* srom is good and is rev < 4 */
		/* top word of sprom contains version and crc8 */
		sromrev = b[SROM_CRCREV] & 0xff;
		/* bcm4401 sroms misprogrammed */
		if (sromrev == 0x10)
			sromrev = 1;
	}

	if (err) {
#ifdef WLTEST
		BS_ERROR(("SROM Crc Error, so see if we could use a default\n"));
		w32 = OSL_PCI_READ_CONFIG(osh, PCI_SPROM_CONTROL, sizeof(uint32));
		if (w32 & SPROM_OTPIN_USE) {
			BS_ERROR(("srom crc failed with OTP, use default vars....\n"));
			vp = base =  mfgsromvars;
			if (sb_chip(sbh) == BCM4311_CHIP_ID) {
				BS_ERROR(("setting the devid to be 4311\n"));
				vp += sprintf(vp, "devid=0x4311");
				vp++;
			}
			bcopy(defaultsromvars, 	vp, MFGSROM_DEFVARSLEN);
			vp += MFGSROM_DEFVARSLEN;
			goto varsdone;
		} else {
#endif /* WLTEST */
			BS_ERROR(("srom crc failed with SPROM....\n"));
			sb_devpath(sbh, devpath, sizeof(devpath));
			sprintf(name, "%ssromrev", devpath);
			if (!(value = getvar(NULL, name))) {
				err = -1;
				goto errout;
			}
			sromrev = (uint8)bcm_strtoul(value, NULL, 0);
			flash = TRUE;
#ifdef WLTEST
		}
#endif /* WLTEST */
	}

	/* srom version check */
	if (sromrev > 5) {
		err = -2;
		goto errout;
	}

	ASSERT(vars);
	ASSERT(count);

	base = vp = MALLOC(osh, VARS_MAX);
	ASSERT(vp);
	if (!vp) {
		err = -2;
		goto errout;
	}

	/* read variables from flash */
	if (flash) {
		if ((err = initvars_flash(osh, &vp, VARS_MAX, devpath)))
			goto errout;
		goto varsdone;
	}

	vp += sprintf(vp, "sromrev=%d", sromrev);
	vp++;

	if (sromrev >= 4) {
		uint16 bfl0, bfl1, bfl3, maclo, macmid, machi;
		uint16 ccode, regrev, ledbh10, ledbh32;
		uint path, pathbase;
		const uint pathbases[MAX_PATH] = {SROM4_PATH0, SROM4_PATH1,
		                                  SROM4_PATH2, SROM4_PATH3};

		vp += sprintf(vp, "boardrev=%d", b[SROM4_BREV]);
		vp++;

		if (sromrev > 4) {
			bfl0 = b[SROM5_BFL0];
			bfl1 = b[SROM5_BFL1];
			bfl2 = b[SROM5_BFL2];
			bfl3 = b[SROM5_BFL3];
			maclo = b[SROM5_MACLO];
			macmid = b[SROM5_MACMID];
			machi = b[SROM5_MACHI];
			ccode = b[SROM5_CCODE];
			regrev = b[SROM5_REGREV];
			ledbh10 = b[SROM5_LEDBH10];
			ledbh32 = b[SROM5_LEDBH32];
		} else {
			bfl0 = b[SROM4_BFL0];
			bfl1 = b[SROM4_BFL1];
			bfl2 = b[SROM4_BFL2];
			bfl3 = b[SROM4_BFL3];
			maclo = b[SROM4_MACLO];
			macmid = b[SROM4_MACMID];
			machi = b[SROM4_MACHI];
			ccode = b[SROM4_CCODE];
			regrev = b[SROM4_REGREV];
			ledbh10 = b[SROM4_LEDBH10];
			ledbh32 = b[SROM4_LEDBH32];
		}
		vp += sprintf(vp, "boardflags=%d", (bfl1 << 16) | bfl0);
		vp++;

		vp += sprintf(vp, "boardflags2=%d", (bfl3 << 16) | bfl2);
		vp++;

		/* The macaddr */
		vp += addmacaddr(vp, "macaddr", machi, macmid, maclo);
		vp++;

		if (ccode == 0)
			vp += sprintf(vp, "ccode=");
		else
			vp += sprintf(vp, "ccode=%c%c", (ccode >> 8), (ccode & 0xff));
		vp++;
		vp += sprintf(vp, "regrev=%d", regrev);
		vp++;

		if ((ledbh10 != 0) && (ledbh10 != 0xffff)) {
			/* ledbh0 */
			vp += sprintf(vp, "ledbh0=%d", (ledbh10 & 0xff));
			vp++;

			/* ledbh1 */
			vp += sprintf(vp, "ledbh1=%d", (ledbh10 >> 8) & 0xff);
			vp++;
		}
		if ((ledbh32 != 0) && (ledbh32 != 0xffff)) {
			/* ledbh2 */
			vp += sprintf(vp, "ledbh2=%d", ledbh32 & 0xff);
			vp++;

			/* ledbh3 */
			vp += sprintf(vp, "ledbh3=%d", (ledbh32 >> 8) & 0xff);
			vp++;
		}

		/* LED Powersave duty cycle (oncount >> 24) (offcount >> 8) */
		w = b[SROM4_LEDDC];
		if (w != 0xffff) {
			w32 = ((uint32)((unsigned char)(w >> 8) & 0xff) << 24) |  /* oncount */
			        ((uint32)((unsigned char)(w & 0xff)) << 8); /* offcount */
			vp += sprintf(vp, "leddc=%d", w32);
			vp++;
		}

		w = b[SROM4_AA];
		vp += sprintf(vp, "aa2g=%d", w & SROM4_AA2G_MASK);
		vp++;
		vp += sprintf(vp, "aa5g=%d", w >> SROM4_AA5G_SHIFT);
		vp++;

		w = b[SROM4_TXRXC];
		if (w != 0xffff) {
			vp += sprintf(vp, "txchain=%d",
				(w & SROM4_TXCHAIN_MASK) >> SROM4_TXCHAIN_SHIFT);
			vp++;
			vp += sprintf(vp, "rxchain=%d",
				(w & SROM4_RXCHAIN_MASK) >> SROM4_RXCHAIN_SHIFT);
			vp++;
			vp += sprintf(vp, "antswitch=%d",
				(w & SROM4_SWITCH_MASK) >> SROM4_SWITCH_SHIFT);
			vp++;
		}

		w = b[SROM4_AG10];
		vp += sprintf(vp, "ag0=%d", w & 0xff);
		vp++;
		vp += sprintf(vp, "ag1=%d", (w >> 8) & 0xff);
		vp++;
		w = b[SROM4_AG32];
		vp += sprintf(vp, "ag2=%d", w & 0xff);
		vp++;
		vp += sprintf(vp, "ag3=%d", (w >> 8) & 0xff);
		vp++;

		/* Fixed power indices when power control is disabled */
		for (i = 0; i < 2; i++) {
			w = b[SROM4_TXPID2G + i];
			vp += sprintf(vp, "txpid2ga%d=%d", 2 * i, w & 0xff);
			vp++;
			vp += sprintf(vp, "txpid2ga%d=%d", (2 * i) + 1, (w >> 8) & 0xff);
			vp++;
			w = b[SROM4_TXPID5G + i];
			vp += sprintf(vp, "txpid5ga%d=%d", 2 * i, w & 0xff);
			vp++;
			vp += sprintf(vp, "txpid5ga%d=%d", (2 * i) + 1, (w >> 8) & 0xff);
			vp++;
			w = b[SROM4_TXPID5GL + i];
			vp += sprintf(vp, "txpid5gla%d=%d", 2 * i, w & 0xff);
			vp++;
			vp += sprintf(vp, "txpid5gla%d=%d", (2 * i) + 1, (w >> 8) & 0xff);
			vp++;
			w = b[SROM4_TXPID5GH + i];
			vp += sprintf(vp, "txpid5gha%d=%d", 2 * i, w & 0xff);
			vp++;
			vp += sprintf(vp, "txpid5gha%d=%d", (2 * i) + 1, (w >> 8) & 0xff);
			vp++;
		}

		/* Per path variables */
		for (path = 0; path < MAX_PATH; path++) {
			pathbase = pathbases[path];
			w = b[pathbase + SROM4_2G_ITT_MAXP];
			vp += sprintf(vp, "itt2ga%d=%d", path, w >> B2G_ITT_SHIFT);
			vp++;
			vp += sprintf(vp, "maxp2ga%d=%d", path, w & B2G_MAXP_MASK);
			vp++;

			for (i = 0; i < 4; i++) {
				vp += sprintf(vp, "pa2gw%da%d=%d", i, path,
				              b[pathbase + SROM4_2G_PA + i]);
				vp++;
			}

			w = b[pathbase + SROM4_5G_ITT_MAXP];
			vp += sprintf(vp, "itt5ga%d=%d", path, w >> B5G_ITT_SHIFT);
			vp++;
			vp += sprintf(vp, "maxp5ga%d=%d", path, w & B5G_MAXP_MASK);
			vp++;

			w = b[pathbase + SROM4_5GLH_MAXP];
			vp += sprintf(vp, "maxp5gla%d=%d", path, w >> B5GL_MAXP_SHIFT);
			vp++;
			vp += sprintf(vp, "maxp5gha%d=%d", path, w & B5GH_MAXP_MASK);
			vp++;

			for (i = 0; i < 4; i++) {
				vp += sprintf(vp, "pa5gw%da%d=%d", i, path,
				              b[pathbase + SROM4_5G_PA + i]);
				vp++;
				vp += sprintf(vp, "pa5glw%da%d=%d", i, path,
				              b[pathbase + SROM4_5GL_PA + i]);
				vp++;
				vp += sprintf(vp, "pa5ghw%da%d=%d", i, path,
				              b[pathbase + SROM4_5GH_PA + i]);
				vp++;
			}
		}

		vp += sprintf(vp, "cck2gpo=%d", b[SROM4_2G_CCKPO]);
		vp++;

		w32 = ((uint32)b[SROM4_2G_OFDMPO + 1] << 16) | b[SROM4_2G_OFDMPO];
		vp += sprintf(vp, "ofdm2gpo=%d", w32);
		vp++;

		w32 = ((uint32)b[SROM4_5G_OFDMPO + 1] << 16) | b[SROM4_5G_OFDMPO];
		vp += sprintf(vp, "ofdm5gpo=%d", w32);
		vp++;

		w32 = ((uint32)b[SROM4_5GL_OFDMPO + 1] << 16) | b[SROM4_5GL_OFDMPO];
		vp += sprintf(vp, "ofdm5glpo=%d", w32);
		vp++;

		w32 = ((uint32)b[SROM4_5GH_OFDMPO + 1] << 16) | b[SROM4_5GH_OFDMPO];
		vp += sprintf(vp, "ofdm5ghpo=%d", w32);
		vp++;

		for (i = 0; i < 8; i++) {
			vp += sprintf(vp, "mcs2gpo%d=%d", i, b[SROM4_2G_MCSPO + i]);
			vp++;
			vp += sprintf(vp, "mcs5gpo%d=%d", i, b[SROM4_5G_MCSPO + i]);
			vp++;
			vp += sprintf(vp, "mcs5glpo%d=%d", i, b[SROM4_5GL_MCSPO + i]);
			vp++;
			vp += sprintf(vp, "mcs5ghpo%d=%d", i, b[SROM4_5GH_MCSPO + i]);
			vp++;
		}

		vp += sprintf(vp, "cddpo=%d", b[SROM4_CDDPO]);
		vp++;
		vp += sprintf(vp, "stbcpo=%d", b[SROM4_STBCPO]);
		vp++;
		vp += sprintf(vp, "bw40po=%d", b[SROM4_BW40PO]);
		vp++;
		vp += sprintf(vp, "bwduppo=%d", b[SROM4_BWDUPPO]);
		vp++;

		goto done;
	}
	if (sromrev == 3) {
		/* New lpphy variables */

		/* Word 40 have the 2.4Ghz switcharch and rssi select values */
		w = b[SROM_BXARSSI2G];
		vp += sprintf(vp, "bxa2g=%d", w >> 12);
		vp++;
		vp += sprintf(vp, "rssisav2g=%d", (w >> 8) & 7);
		vp++;
		vp += sprintf(vp, "rssismc2g=%d", (w >> 4) & 0xf);
		vp++;
		vp += sprintf(vp, "rssismf2g=%d", w & 0xf);
		vp++;

		/* Word 41 have the 5Ghz switcharch and rssi values */
		w = b[SROM_BXARSSI5G];
		vp += sprintf(vp, "bxa5g=%d", w >> 12);
		vp++;
		vp += sprintf(vp, "rssisav5g=%d", (w >> 8) & 7);
		vp++;
		vp += sprintf(vp, "rssismc5g=%d", (w >> 4) & 0xf);
		vp++;
		vp += sprintf(vp, "rssismf5g=%d", w & 0xf);
		vp++;

		/* Words 42+43 are 5Ghz (hi/mid/low) and 2.4Ghz trisolation values */
		w = b[SROM_TRI52G];
		vp += sprintf(vp, "tri5g=%d", w >> 8);
		vp++;
		vp += sprintf(vp, "tri2g=%d", w & 0xff);
		vp++;

		w = b[SROM_TRI5GHL];
		vp += sprintf(vp, "tri5gh=%d", w >> 8);
		vp++;
		vp += sprintf(vp, "tri5gl=%d", w & 0xff);
		vp++;

		/* Word 45 are 5Ghz and 2.4Ghz rx power offsets */
		w = b[SROM_RXPO52G];
		vp += sprintf(vp, "rxpo5g=%d", w >> 8);
		vp++;
		vp += sprintf(vp, "rxpo2g=%d", w & 0xff);
		vp++;

		/* LED Powersave duty cycle (oncount >> 24) (offcount >> 8) */
		w = b[SROM3_LEDDC];
		w32 = ((uint32)((unsigned char)(w >> 8) & 0xff) << 24) |  /* oncount */
		        ((uint32)((unsigned char)(w & 0xff)) << 8); /* offcount */
		vp += sprintf(vp, "leddc=%d", w32);
		vp++;

		/* Single mac address */
		vp += addmacaddr(vp, "macaddr", b[SROM3_MACHI], b[SROM3_MACMID], b[SROM3_MACLO]);
		vp++;

		/* Regulatory revision is part of the opo word */
		w = b[SROM_OPO];
		vp += sprintf(vp, "regrev=%d", w >> 8);
		vp++;

		/* Boardflags2 moved in rev 3 */
		bfl2 = b[SROM3_BFL2];
	} else {
		/* il0macaddr */
		vp += addmacaddr(vp, "il0macaddr", b[SROM_MACHI_IL0], b[SROM_MACMID_IL0],
		                 b[SROM_MACLO_IL0]);
		vp++;


		/* et0macaddr */
		vp += addmacaddr(vp, "et0macaddr", b[SROM_MACHI_ET0], b[SROM_MACMID_ET0],
		                 b[SROM_MACLO_ET0]);
		vp++;

		/* et1macaddr */
		vp += addmacaddr(vp, "et1macaddr", b[SROM_MACHI_ET1], b[SROM_MACMID_ET1],
		                 b[SROM_MACLO_ET1]);
		vp++;

		/*
		 * Enet phy settings one or two singles or a dual
		 * Bits 4-0 : MII address for enet0 (0x1f for not there)
		 * Bits 9-5 : MII address for enet1 (0x1f for not there)
		 * Bit 14   : Mdio for enet0
		 * Bit 15   : Mdio for enet1
		 */
		w = b[SROM2_ENETPHY];
		vp += sprintf(vp, "et0phyaddr=%d", (w & 0x1f));
		vp++;
		vp += sprintf(vp, "et1phyaddr=%d", ((w >> 5) & 0x1f));
		vp++;
		vp += sprintf(vp, "et0mdcport=%d", ((w >> 14) & 0x1));
		vp++;
		vp += sprintf(vp, "et1mdcport=%d", ((w >> 15) & 0x1));
		vp++;

		/* Boardflags2 */
		bfl2 = b[SROM_BFL2];
	}

	/* New section takes over the 4th hardware function space */
	/* Word 29 is max power 11a high/low */
	w = b[SROM_WL1LHMAXP];
	vp += sprintf(vp, "pa1himaxpwr=%d", w & 0xff);
	vp++;
	vp += sprintf(vp, "pa1lomaxpwr=%d", (w >> 8) & 0xff);
	vp++;

	/* Words 30-32 set the 11alow pa settings,
	 * 33-35 are the 11ahigh ones.
	 */
	for (i = 0; i < 3; i++) {
		vp += sprintf(vp, "pa1lob%d=%d", i, b[SROM_WL1LPAB0 + i]);
		vp++;
		vp += sprintf(vp, "pa1hib%d=%d", i, b[SROM_WL1HPAB0 + i]);
		vp++;
	}

	w = b[SROM_CCODE];
	if (w == 0)
		vp += sprintf(vp, "ccode=");
	else
		vp += sprintf(vp, "ccode=%c%c", (w >> 8), (w & 0xff));
	vp++;

	/* Word 46 has board rev, antennas 0/1 & Country code/control */
	w = b[SROM_AABREV];
	vp += sprintf(vp, "boardrev=%d", w & 0xff);
	vp++;

	if (sromrev == 1) {
		vp += sprintf(vp, "cc=%d", (w >> 8) & 0xf);
		vp++;
	}

	vp += sprintf(vp, "aa2g=%d", (w >> 12) & 0x3);
	vp++;

	vp += sprintf(vp, "aa5g=%d", (w >> 14) & 0x3);
	vp++;

	/* Words 47-49 set the (wl) pa settings */
	for (i = 0; i < 3; i++) {
		vp += sprintf(vp, "pa0b%d=%d", i, b[SROM_WL0PAB0 + i]);
		vp++;
		vp += sprintf(vp, "pa1b%d=%d", i, b[SROM_WL1PAB0 + i]);
		vp++;
	}

	/*
	 * Words 50-51 set the customer-configured wl led behavior.
	 * 8 bits/gpio pin.  High bit:  activehi=0, activelo=1;
	 * LED behavior values defined in wlioctl.h .
	 */
	w = b[SROM_LEDBH10];
	if ((w != 0) && (w != 0xffff)) {
		/* ledbh0 */
		vp += sprintf(vp, "ledbh0=%d", (w & 0xff));
		vp++;

		/* ledbh1 */
		vp += sprintf(vp, "ledbh1=%d", (w >> 8) & 0xff);
		vp++;
	}
	w = b[SROM_LEDBH32];
	if ((w != 0) && (w != 0xffff)) {
		/* ledbh2 */
		vp += sprintf(vp, "ledbh2=%d", w & 0xff);
		vp++;

		/* ledbh */
		vp += sprintf(vp, "ledbh3=%d", (w >> 8) & 0xff);
		vp++;
	}

	/* Word 52 is max power 0/1 */
	w = b[SROM_WL10MAXP];
	vp += sprintf(vp, "pa0maxpwr=%d", w & 0xff);
	vp++;
	vp += sprintf(vp, "pa1maxpwr=%d", (w >> 8) & 0xff);
	vp++;

	/* Word 56 is idle tssi target 0/1 */
	w = b[SROM_ITT];
	vp += sprintf(vp, "pa0itssit=%d", w & 0xff);
	vp++;
	vp += sprintf(vp, "pa1itssit=%d", (w >> 8) & 0xff);
	vp++;

	/* Word 57 is boardflags, if not programmed make it zero */
	w32 = (uint32)b[SROM_BFL];
	if (sromrev > 1) w32 |= bfl2 << 16;
	vp += sprintf(vp, "boardflags=%d", w32);
	vp++;

	/* Word 58 is antenna gain 0/1 */
	w = b[SROM_AG10];
	vp += sprintf(vp, "ag0=%d", w & 0xff);
	vp++;

	vp += sprintf(vp, "ag1=%d", (w >> 8) & 0xff);
	vp++;

	if (sromrev > 1) {
		/* Word 60 OFDM tx power offset from CCK level */
		/* OFDM Power Offset - opo */
		vp += sprintf(vp, "opo=%d", b[SROM_OPO] & 0xff);
		vp++;
	}

	/* final nullbyte terminator */
done:	*vp++ = '\0';

	ASSERT((vp - base) <= VARS_MAX);

varsdone:
	err = initvars_table(osh, base, vp, vars, count);

errout:
#ifdef WLTEST
	if (base && (base != mfgsromvars))
#else
	if (base)
#endif
		MFREE(osh, base, VARS_MAX);

	MFREE(osh, b, SROM_MAX);
	return err;
}

/*
 * Read the cis and call parsecis to initialize the vars.
 * Return 0 on success, nonzero on error.
 */
static int
initvars_cis_pcmcia(void *sbh, osl_t *osh, char **vars, uint *count)
{
	uint8 *cis = NULL;
	int rc;
	uint data_sz;

	data_sz = (sb_pcmciarev(sbh) == 1) ? (SPROM_SIZE * 2) : CIS_SIZE;

	if ((cis = MALLOC(osh, data_sz)) == NULL)
		return (-2);

	if (sb_pcmciarev(sbh) == 1) {
		if (srom_read(PCMCIA_BUS, (void *)NULL, osh, 0, data_sz, (uint16 *)cis)) {
			MFREE(osh, cis, data_sz);
			return (-1);
		}
		/* fix up endianess for 16-bit data vs 8-bit parsing */
		ltoh16_buf((uint16 *)cis, data_sz);
	} else
		OSL_PCMCIA_READ_ATTR(osh, 0, cis, data_sz);

	rc = srom_parsecis(osh, &cis, 1, vars, count);

	MFREE(osh, cis, data_sz);

	return (rc);
}


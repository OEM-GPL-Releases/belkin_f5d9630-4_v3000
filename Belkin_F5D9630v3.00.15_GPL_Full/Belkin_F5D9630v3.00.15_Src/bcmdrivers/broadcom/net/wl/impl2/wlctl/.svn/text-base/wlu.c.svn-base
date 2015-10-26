/*
 * Common code for wl command-line swiss-army-knife utility
 *
 * Copyright 2006, Broadcom Corporation
 * All Rights Reserved.                
 *                                     
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;   
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior      
 * written permission of Broadcom Corporation.                            
 *
 * Policy notes:
 * This source file generates both the "wl" command and the
 * more restricted "wl-tool" manufacturing test command (-DWL_TOOL).
 * - wl driver wlc_ioctl() commands which are enclosed within #ifdef BCMINTERNAL
 * should be enclosed within #ifdef BCMINTERNAL in wlu.c .
 * - exposing any new commands in wl-tool requires an "ok" from romanb.
 *
 * $Id$
 */


#if	defined(_CFE_)
#include <lib_types.h>
#include <lib_string.h>
#include <lib_printf.h>
#include <lib_malloc.h>
#include <cfe_error.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#endif /* defined(_CFE_) */

#include <typedefs.h>
#include <epivers.h>
#include <proto/ethernet.h>
#include <proto/802.11.h>
#include <proto/802.1d.h>
#include <proto/802.11e.h>
#include <proto/wpa.h>
#include <proto/eapol.h>
#include <wlioctl.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <bcmwifi.h>
#include "wlu.h"

#if defined(__NetBSD__) || defined(linux) || defined(MACOSX)
#define stricmp strcasecmp
#define strnicmp strncasecmp
#elif	defined(UNDER_CE) || defined(_CRT_SECURE_NO_DEPRECATE)
#define stricmp _stricmp
#define strnicmp _strnicmp
#elif	defined(_CFE_)
#include <bcmutils.h>
#include <osl.h>
#define isalnum(c) bcm_isalnum(c)
#define isalpha(c) bcm_isalpha(c)
#define iscntrl(c) bcm_iscntrl(c)
#define isdigit(c) bcm_isdigit(c)
#define isgraph(c) bcm_isgraph(c)
#define islower(c) bcm_islower(c)
#define isprint(c) bcm_isprint(c)
#define ispunct(c) bcm_ispunct(c)
#define isspace(c) bcm_isspace(c)
#define isupper(c) bcm_isupper(c)
#define isxdigit(c) bcm_isxdigit(c)
#define stricmp(s1, s2) lib_strcmpi((s1), (s2))
#define strtoul(nptr, endptr, base) bcm_strtoul((nptr), (endptr), (base))
#define tolower(c) (bcm_isupper((c)) ? ((c) + 'a' - 'A') : (c))
#define fprintf(stream, fmt, args...) xprintf(fmt, ## args)
#define fputs(s, stream) puts(s)
#define malloc(size) KMALLOC((size), 0)
#define free(ptr) KFREE(ptr)
#define strnicmp(s1, s2, len) strncmp((s1), (s2), (len))
#define strspn(s, accept) (0)
#define strtol(nptr, endptr, base) bcm_strtoul((nptr), (endptr), (base))
#endif /* __NetBSD__ */

cmd_func_t wl_int;
static cmd_func_t wl_print_deprecate;
static cmd_func_t wl_void, wl_rssi, wl_phy_rssi_ant, wl_gmode;
static cmd_func_t wlu_dump, wlu_srdump, wlu_srwrite, wl_rate_mrate, wl_phy_rate;
static cmd_func_t wl_channel, wl_chanspec, wl_radio, wl_version, wl_list;
static cmd_func_t wl_band, wl_bandlist, wl_phylist, wl_out;
static cmd_func_t wl_join, wl_tssi, wl_txpwr, wl_atten, wl_evm, wl_country;
static cmd_func_t wl_txpwr1;
static cmd_func_t wl_maclist, wl_get_pktcnt, wl_upgrade;
static cmd_func_t wl_maclist_1;
static cmd_func_t wl_rateset, wl_interfere;
static cmd_func_t wl_radar_args, wl_dfs_status;
static cmd_func_t wl_get_txpwr_limit, wl_get_current_power, wl_get_instant_power;
static cmd_func_t wl_var_get, wl_var_getint, wl_var_getandprintstr;
static cmd_func_t wl_var_setint, wl_addwep, wl_rmwep;
static cmd_func_t wl_nvdump, wl_nvget, wl_nvset, wl_sta_info, wl_chan_info;
static cmd_func_t wl_wme_ac_req, wl_add_ie, wl_del_ie, wl_list_ie;
static cmd_func_t wl_wme_apsd_sta, wl_wme_dp, wl_lifetime;
static cmd_func_t wl_rand, wl_otpw, wl_counters, wl_assoc_info, wl_wme_counters;
static cmd_func_t wl_bitvec128, wl_diag, wl_var_void;
static cmd_func_t wl_auto_channel_sel;
static cmd_func_t wl_bsscfg_int, wl_bsscfg_enable;
static cmd_func_t wl_msglevel, wl_plcphdr, wl_reg, wl_macreg, wl_band_elm;
static cmd_func_t wl_rateparam, wl_wepstatus, wl_status, wl_spect;
static cmd_func_t wl_sup_rateset, wl_scan, wl_send_csa;
static cmd_func_t wl_dump_chanlist, wl_primary_key, wl_measure_req, wl_send_quiet;
static cmd_func_t wl_dump_chanspecs, wl_cur_mcsset;
static cmd_func_t wl_wsec, wl_keys, wl_wsec_test;
static cmd_func_t wl_channels_in_country;
static cmd_func_t wl_wpa_auth, wl_tsc, wl_deauth_rc, wl_ssid;
static cmd_func_t wl_wds_wpa_role_old, wl_wds_wpa_role, wl_set_pmk;
static cmd_func_t wl_rm_request, wl_rm_report;
static cmd_func_t wl_join_pref, wl_assoc_pref;
static cmd_func_t wl_dump_networks, wl_mac, wl_revinfo;
static cmd_func_t wl_cac, wl_tslist, wl_tspec;
static cmd_func_t wl_varstr, wl_var_setintandprintstr;
static cmd_func_t wl_caldump;
static cmd_func_t wl_test_tssi, wl_test_tssi_offs;
#ifdef DSLCPE
/* phy types */
#define	PHY_TYPE_A		0
#define	PHY_TYPE_B		1
#define	PHY_TYPE_G		2
#define	PHY_TYPE_N		4
#define	PHY_TYPE_NULL		0xf
static cmd_func_t wl_assoclist_info;
#endif

#if defined(DSLCPE) || defined(linux)
#include <unistd.h>
static void
sleep_ms(const unsigned int ms)
{
	usleep(1000*ms);
}
#else
#error "sleep_ms() not defined for this OS!!!"
#endif /* defined(linux) */

#ifdef BCMWPA2
static cmd_func_t wl_pmkid_info;
#endif


static cmd_func_t wl_ampdu_tid;
static cmd_func_t wl_ampdu_send_addba;
static cmd_func_t wl_ampdu_send_delba;

static cmd_func_t wl_gpioout;

static cmd_func_t wl_nrate, wl_antsel;
static cmd_func_t wl_txfifo_sz;

static void wl_txpwr_array_print(uint8 *pwr, int cck, int mimo);
static void wl_txpwr_range_print(uint8 *pwr, int start, int count, const char* label, int *newline);
static void wl_txpwr_row_print(uint8 *pwr, int start, int count);
static int wl_array_uniform(uint8 *pwr, int start, int count);
static int wl_curpower_legacy(void *wl);

static int wl_parse_rateset(wl_rateset_t* rs, char **argv);

static void dump_networks(char *buf);
static void dump_bss_info(wl_bss_info_t *bi);
static void wl_dump_wpa_rsn_ies(uint8* cp, uint len);
static void wl_rsn_ie_dump(bcm_tlv_t *ie);

/* 802.11i/WPA RSN IE parsing utilities */
typedef struct {
	uint16 version;
	wpa_suite_mcast_t *mcast;
	wpa_suite_ucast_t *ucast;
	wpa_suite_auth_key_mgmt_t *akm;
	uint8 *capabilities;
} rsn_parse_info_t;

static int wl_rsn_ie_parse_info(uint8* buf, uint len, rsn_parse_info_t *rsn);
static uint wl_rsn_ie_decode_cntrs(uint cntr_field);

static int wl_parse_channel_list(char* list_str, uint16* channel_list, int channel_num);

static uint16 wl_qdbm_to_mw(uint8 qdbm);
static uint8 wl_mw_to_qdbm(uint16 mw);

static int wl_cfg_option(char **argv, const char *fn_name, int *bsscfg_idx, int *consumed);
static int get_oui_bytes(uchar *oui_str, uchar *oui);
static int get_ie_data(uchar *data_str, uchar *ie_data, int len);
static void wl_printrate(int val);
static int rate_string2int(char *s);
static char *rate_int2string(char *buf, int val);

static int wl_get_scan(void *wl, int opc, char *buf, uint buf_len);
static int wl_var_getbuf(void *wl, const char *iovar, void *param, int param_len, void **bufptr);
static int wl_var_setbuf(void *wl, const char *iovar, void *param, int param_len);

static uint wl_iovar_mkbuf(const char *name, char *data, uint datalen, char *buf, uint buflen,
                           int *perr);
static int wl_iovar_getbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
static int wl_iovar_setbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
static int wl_iovar_get(void *wl, const char *iovar, void *outbuf, int len);
static int wl_iovar_set(void *wl, const char *iovar, void *param, int paramlen);
static int wl_iovar_getint(void *wl, const char *iovar, int *pval);
static int wl_iovar_setint(void *wl, const char *iovar, int val);

static int wl_bssiovar_mkbuf(const char *iovar, int bssidx, void *param,
	int paramlen, void *bufptr, int buflen, int *perr);
static int wl_bssiovar_setbuf(void* wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen);
static int wl_bssiovar_getbuf(void* wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen);
static int wl_bssiovar_set(void *wl, const char *iovar, int bssidx, void *param, int paramlen);
static int wl_bssiovar_get(void *wl, const char *iovar, int bssidx, void *outbuf, int len);
static int wl_bssiovar_setint(void *wl, const char *iovar, int bssidx, int val);
static int wl_bssiovar_getint(void *wl, const char *iovar, int bssidx, int *pval);

static int wl_vndr_ie(void *wl, const char *command, char **argv);
static int hexstrtobitvec(const char *cp, uchar *bitvec, int veclen);
static void wl_join_pref_print_ie(bcm_tlv_t *ie);
static void wl_join_pref_print_akm(uint8* suite);
static void wl_join_pref_print_cipher_suite(uint8* suite);

#define MINIOPT_MAXKEY	128	/* Max options */
typedef struct miniopt {
	const char* name;	/* name for prompt in error strings */
	const char* flags;	/* set of chars that are option flags
				 * with no args
				 */
	int consumed;		/* number of argv entries cosumed in
				 * the most recent call to miniopt()
				 */
	bool opt_end;		/* at end of options since a "--" flag
				 * was encountered
				 */
	bool positional;	
	bool good_int;		/* 'val' member is the result of a sucessful
				 * strtol conversion of the option value
				 */
	char opt;		
	char key[MINIOPT_MAXKEY];	
	char* valstr;		/* positional param, or value for the option,
				 * or null if the option had
				 * no accompanying value
				 */
	int val;		/* strtol translation of valstr */
} miniopt_t;

void miniopt_init(miniopt_t *t, const char* name, const char* flags);
int miniopt(miniopt_t *t, char **argv);

/* some OSes (FC4) have trouble allocating (kmalloc) 128KB worth of memory,
 * hence keeping WL_DUMP_BUF_LEN below that
 */
#define WL_DUMP_BUF_LEN (127 * 1024)

#define OUI_STR_SIZE	8	/* OUI string size */
#define MAX_OUI_SIZE	3	/* MAX  OUI size */
#define MAX_BYTE_CHARS	2	/* MAX num chars */
#define MAX_DATA_COLS	16	/* MAX data cols */
#define DIV_QUO(num, div) ((num)/div)  /* Return the quotient of division to avoid floats */
#define DIV_REM(num, div) (((num%div) * 100)/div) /* Return the remainder of division */

static char buf[WLC_IOCTL_MAXLEN];

/* integer output format, default to signed integer */
uint8 int_fmt = INT_FMT_DEC;

/*
 * Country names and abbreviations from ISO 3166
 */
typedef struct {
	const char *name;	/* Long name */
	const char *abbrev;	/* Abbreviation */
} cntry_name_t;
cntry_name_t cntry_names[];	/* At end of this file */

typedef struct {
	uint value;
	const char *string;
} dbg_msg_t;

/* If the new command needs to be part of 'wc.exe' tool used for WMM,
 * be sure to modify wc_cmds[] array as well
 */
cmd_t wl_cmds[] = {
	{ "ver", wl_version, -1, -1,
	"get version information" },
	{ "cmds", wl_list, -1, -1,
	"generate a short list of available commands"},
	{ "up",	wl_void, -1, WLC_UP,
	"reinitialize and mark adapter up (operational)" },
	{ "down", wl_void, -1, WLC_DOWN,
	"reset and mark adapter down (disabled)" },
	{ "out", wl_out, -1, WLC_OUT,
	"mark adapter down but do not reset hardware(disabled)\n"
	"\tOn dualband cards, cards must be bandlocked before use."},
	{ "clk", wl_int, WLC_GET_CLK, WLC_SET_CLK,
	"set board clock state. return error for set_clk attempt if the driver is not down\n"
	"\t0: clock off\n"
	"\t1: clock on" },
	{ "restart", wl_void, -1, WLC_RESTART,
	"Restart driver.  Driver must already be down."},
	{ "reboot", wl_void, -1, WLC_REBOOT,
	"Reboot platform"},
	{ "ucflags", wl_int, WLC_GET_UCFLAGS, WLC_SET_UCFLAGS,
	"Get/Set ucode flags"},
	{ "radio", wl_radio, WLC_GET_RADIO, WLC_SET_RADIO,
	"Set the radio on or off.\n"
	"\t\"on\" or \"off\"" },
	{ "dump", wlu_dump, WLC_GET_VAR, -1,
	"Give suboption \"list\" to list various suboptions" },
	{ "srclear", wlu_srwrite, -1, WLC_SET_SROM,
	"Clearthe srom" },
	{ "srdump", wlu_srdump, WLC_GET_SROM, -1,
	"print contents of SPROM to stdout" },
	{ "srwrite", wlu_srwrite, -1, WLC_SET_SROM,
	"Write the srom" },
	{ "nvram_dump", wl_nvdump, WLC_NVRAM_DUMP, -1,
	"print nvram variables to stdout" },
	{ "nvset", wl_nvset, -1, WLC_NVRAM_SET,
	"set an nvram variable\n"
	"\tname=value (no spaces around \'=\')" },
	{ "nvget", wl_nvget, WLC_NVRAM_GET, -1,
	"get the value of an nvram variable" },
	{ "nvram_get", wl_nvget, WLC_NVRAM_GET, -1,
	"get the value of an nvram variable" },
	{ "revinfo", wl_revinfo, WLC_GET_REVINFO, -1,
	"get hardware revision information" },
	{ "msglevel", wl_msglevel, WLC_GET_MSGLEVEL, WLC_SET_MSGLEVEL,
	"set driver console debugging message bitvector\n"
	"\ttype \'wl msglevel ?\' for values" },
	{ "PM", wl_int, WLC_GET_PM, WLC_SET_PM,
	"set driver power management mode:\n"
	"\t0: CAM (constantly awake)\n"
	"\t1: PS  (power-save)\n"
	"\t2: FAST PS mode" },
	{ "wake", wl_int, WLC_GET_WAKE, WLC_SET_WAKE,
	"set driver power-save mode sleep state:\n"
	"\t0: core-managed\n"
	"\t1: awake" },
	{ "promisc", wl_int, WLC_GET_PROMISC, WLC_SET_PROMISC,
	"set promiscuous mode ethernet address reception\n"
	"\t0 - disable\n"
	"\t1 - enable" },
	{ "monitor", wl_int, WLC_GET_MONITOR, WLC_SET_MONITOR,
	"set monitor mode\n"
	"\t0 - disable\n"
	"\t1 - enable active monitor mode (interface still operates)" },
	{ "frag", wl_print_deprecate, -1, -1, "Deprecated. Use fragthresh." },
	{ "rts", wl_print_deprecate, -1, -1, "Deprecated. Use rtsthresh." },
	{ "cwmin", wl_int, WLC_GET_CWMIN, WLC_SET_CWMIN,
	"Set the cwmin.  (integer [1, 255])" },
	{ "cwmax", wl_int, WLC_GET_CWMAX, WLC_SET_CWMAX,
	"Set the cwmax.  (integer [256, 2047])" },
	{ "srl", wl_int, WLC_GET_SRL, WLC_SET_SRL,
	"Set the short retry limit.  (integer [1, 255])" },
	{ "lrl", wl_int, WLC_GET_LRL, WLC_SET_LRL,
	"Set the long retry limit.  (integer [1, 255])" },
	{ "rate", wl_rate_mrate, WLC_GET_RATE, -1,
	"force a fixed rate:\n"
	"\tvalid values for 802.11a are (6, 9, 12, 18, 24, 36, 48, 54)\n"
	"\tvalid values for 802.11b are (1, 2, 5.5, 11)\n"
	"\tvalid values for 802.11g are (1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54)\n"
	"\t-1 (default) means automatically determine the best rate" },
	{ "mrate", wl_rate_mrate, -1, -1, /* Deprecated. Use "bg_mrate" or "a_mrate" */
	"force a fixed multicast rate:\n"
	"\tvalid values for 802.11a are (6, 9, 12, 18, 24, 36, 48, 54)\n"
	"\tvalid values for 802.11b are (1, 2, 5.5, 11)\n"
	"\tvalid values for 802.11g are (1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54)\n"
	"\t-1 (default) means automatically determine the best rate" },
	{ "a_rate", wl_phy_rate, WLC_GET_VAR, WLC_SET_VAR,
	"force a fixed rate for the A PHY:\n"
	"\tvalid values for 802.11a are (6, 9, 12, 18, 24, 36, 48, 54)\n"
	"\t-1 (default) means automatically determine the best rate" },
	{ "a_mrate", wl_phy_rate, WLC_GET_VAR, WLC_SET_VAR,
	"force a fixed multicast rate for the A PHY:\n"
	"\tvalid values for 802.11a are (6, 9, 12, 18, 24, 36, 48, 54)\n"
	"\t-1 (default) means automatically determine the best rate" },
	{ "bg_rate", wl_phy_rate, WLC_GET_VAR, WLC_SET_VAR,
	"force a fixed rate for the B/G PHY:\n"
	"\tvalid values for 802.11b are (1, 2, 5.5, 11)\n"
	"\tvalid values for 802.11g are (1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54)\n"
	"\t-1 (default) means automatically determine the best rate" },
	{ "bg_mrate", wl_phy_rate, WLC_GET_VAR, WLC_SET_VAR,
	"force a fixed multicast rate for the B/G PHY:\n"
	"\tvalid values for 802.11b are (1, 2, 5.5, 11)\n"
	"\tvalid values for 802.11g are (1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54)\n"
	"\t-1 (default) means automatically determine the best rate" },
	{ "infra", wl_int, WLC_GET_INFRA, WLC_SET_INFRA,
	"Set Infrastructure mode: 0 (IBSS) or 1 (Infra BSS)" },
	{ "ap", wl_int, WLC_GET_AP, WLC_SET_AP,
	"Set AP mode: 0 (STA) or 1 (AP)" },
	{ "bssid", wl_mac, WLC_GET_BSSID, -1,
	"Get the BSSID value, error if STA and not associated"},
	{ "channel", wl_channel, WLC_GET_CHANNEL, WLC_SET_CHANNEL,
	"Set the channel:\n"
	"\tvalid channels for 802.11b/g (2.4GHz band) are 1 through 14\n"
	"\tvalid channels for 802.11a  (5 GHz band) are:\n"
	"\t\t36, 40, 44, 48, 52, 56, 60, 64,\n"
	"\t\t100, 104, 108, 112, 116,120, 124, 128, 132, 136, 140,\n"
	"\t\t149, 153, 157, 161,\n"
	"\t\t184, 188, 192, 196, 200, 204, 208, 212, 216"},
	{ "cur_mcsset", wl_cur_mcsset, WLC_GET_VAR, -1,
	"Get the current mcs set"
	},
	{ "chanspecs", wl_dump_chanspecs, WLC_GET_VAR, -1,
	"Get all the valid chanspecs (default: all within current locale):\n"
	"\t-b band (5(a) or 2(b/g))\n"
	"\t-w bandwidth, 10,20 or 40\n"
	"\t[-c country_abbrev]\n"
	},
	{ "chanspec", wl_chanspec, WLC_GET_VAR, WLC_SET_VAR,
	"Set <channel>[a,b][n][u,l]\n"
	"\tchannel number (0-224)\n"
	"\tband a=5G, b=2G, default to 2G if channel <= 14\n"
	"\tbandwidth, n=10, non for 20 & 40\n"
	"\tctl sideband, l=lower, u=upper\n"
	"OR Set channel with legacy format:\n"
	"\t-c channel number (0-224)\n"
	"\t-b band (5(a) or 2(b/g))\n"
	"\t-w bandwidth, 10,20 or 40\n"
	"\t-s ctl sideband, -1=lower, 0=none, 1=upper"},
	{ "dfs_channel_forced", wl_chanspec, WLC_GET_VAR, WLC_SET_VAR,
	"Set <channel>[a,b][n][u,l]\n"
	"\tchannel number (0-224)\n"
	"\tband a=5G, b=2G, default to 2G if channel <= 14\n"
	"\tbandwidth, n=10, non for 20 & 40\n"
	"\tctl sideband, l=lower, u=upper\n"},
	{ "tssi", wl_tssi, WLC_GET_TSSI, -1,
	"Get the tssi value from radio" },
	{ "txpwr", wl_txpwr, -1, -1, /* Deprecated. Use "txpwr1" */
	"Set tx power in milliwatts.  Range [1, 84]." },
	{ "txpwr1", wl_txpwr1, WLC_GET_VAR, WLC_SET_VAR,
	"Set tx power in in various units. Choose one of (default: dbm): \n"
	"\t-d dbm units\n"
	"\t-q quarter dbm units\n"
	"\t-m milliwatt units\n"
	"Can be combined with:\n"
	"\t-o turn on override to disable regulatory and other limitations\n"
	"Use wl txpwr -1 to restore defaults"},
	{ "txpathpwr", wl_int, WLC_GET_TX_PATH_PWR, WLC_SET_TX_PATH_PWR,
	"Turn the tx path power on or off on 2050 radios" },
	{ "txpwrlimit", wl_get_txpwr_limit, WLC_CURRENT_PWR, -1,
	"Return current tx power limit" },
	{ "powerindex", wl_int, WLC_GET_PWRIDX, WLC_SET_PWRIDX,
	"Set the transmit power for A band(0-63).\n"
	"\t-1 - default value" },
	{ "atten", wl_atten, WLC_GET_ATTEN, WLC_SET_ATTEN,
	"Set the transmit attenuation for B band. Args: bb radio txctl1.\n"
	"\tauto to revert to automatic control\n"
	"\tmanual to supspend automatic control" },
	{ "phyreg", wl_reg, WLC_GET_PHYREG, WLC_SET_PHYREG,
	"Get/Set a phy register:\n"
	"\toffset [ value ] [ band ]" },
	{ "radioreg", wl_reg, WLC_GET_RADIOREG, WLC_SET_RADIOREG,
	"Get/Set a radio register:\n"
	"\toffset [ value ] [ band ]" },
	{ "shmem", wl_reg, WLC_GET_SHMEM, WLC_SET_SHMEM,
	"Get/Set a shared memory location:\n"
	"\toffset [ value ] [ band ]" },
	{ "macreg", wl_macreg, WLC_R_REG, WLC_W_REG,
	"Get/Set any mac registers(include IHR and SB):\n"
	"\tmacreg offset size[2,4] [value] [ band ]" },
	{ "ucantdiv", wl_int, WLC_GET_UCANTDIV, WLC_SET_UCANTDIV,
	"Enable/disable ucode antenna diversity (1/0 or on/off)" },
	{ "gpioout", wl_gpioout, -1, -1,
	"Set any GPIO pins to any value. Use with caution as GPIOs would be "
	"assigned to chipcommon\n"
	"\tUsage: gpiomask gpioval"},
	{ "ampdu_tid", wl_ampdu_tid, WLC_GET_VAR, WLC_SET_VAR,
	"enable/disable per-tid ampdu; usage: wl ampdu_tid <tid> [0/1]" },
	{ "ampdu_send_addba", wl_ampdu_send_addba, WLC_GET_VAR, WLC_SET_VAR,
	"send addba to specified ea-tid; usage: wl ampdu_send_addba <tid> <ea>" },
	{ "ampdu_send_delba", wl_ampdu_send_delba, WLC_GET_VAR, WLC_SET_VAR,
	"send delba to specified ea-tid; usage: wl ampdu_send_delba <tid> <ea>" },
	{ "ampdu_clear_dump", wl_var_void, -1, WLC_SET_VAR,
	"clear ampdu counters"},
	{ "antdiv", wl_int, WLC_GET_ANTDIV, WLC_SET_ANTDIV,
	"Set antenna diversity for rx\n"
	"\t0 - force use of antenna 0\n"
	"\t1 - force use of antenna 1\n"
	"\t3 - automatic selection of antenna diversity" },
	{ "txant", wl_int, WLC_GET_TXANT, WLC_SET_TXANT,
	"Set the transmit antenna\n"
	"\t0 - force use of antenna 0\n"
	"\t1 - force use of antenna 1\n"
	"\t3 - use the RX antenna selection that was in force during\n"
	"\t    the most recently received good PLCP header" },
	{ "plcphdr", wl_plcphdr, WLC_GET_PLCPHDR, WLC_SET_PLCPHDR,
	"Set the plcp header.\n"
	"\t\"long\" or \"auto\" or \"debug\"" },
	{ "phytype", wl_int, WLC_GET_PHYTYPE, -1,
	"Get phy type" },
	{ "rateparam", wl_rateparam, -1, WLC_SET_RATE_PARAMS,
	"set driver rate selection tunables\n"
	"\targ 1: tunable id\n"
	"\targ 2: tunable value" },
	{ "wepstatus", wl_wepstatus, -1, -1, /* Deprecated. Use "wsec" */
	"Set or Get WEP status\n"
	"\twepstatus [on|off]" },
	{ "primary_key", wl_primary_key, WLC_GET_KEY_PRIMARY, WLC_SET_KEY_PRIMARY,
	"Set or get index of primary key" },
	{ "addwep", wl_addwep, -1, WLC_SET_KEY,
	"Set an encryption key.  The key must be 5, 13 or 16 bytes long, or\n"
	"\t10, 26, 32, or 64 hex digits long.  The encryption algorithm is\n"
	"\tautomatically selected based on the key size. keytype is accepted\n"
	"\tonly when key length is 16 bytes/32 hex digits and specifies\n"
	"\twhether AES-OCB or AES-CCM encryption is used. Default is ccm.\n"
	"\taddwep <keyindex> <keydata> [ocb | ccm] [notx] [xx:xx:xx:xx:xx:xx]" },
	{ "rmwep", wl_rmwep, -1, WLC_SET_KEY,
	"Remove the encryption key at the specified key index." },
	{ "keys", wl_keys, WLC_GET_KEY, -1,
	"Prints a list of the current WEP keys" },
	{ "tsc", wl_tsc, WLC_GET_KEY_SEQ, -1,
	"Print Tx Sequence Couter for key at specified key index." },
	{ "wsec_test", wl_wsec_test, -1, WLC_SET_WSEC_TEST,
	"Generate wsec errors\n"
	"\twsec_test <test_type> <keyindex|xx:xx:xx:xx:xx:xx>\n"
	"\ttype \'wl wsec_test ?\' for test_types" },
	{ "tkip_countermeasures", wl_int, -1, WLC_TKIP_COUNTERMEASURES,
	"Enable or disable TKIP countermeasures (TKIP-enabled AP only)\n"
	"\t0 - disable\n"
	"\t1 - enable" },
	{ "wsec_restrict", wl_bsscfg_int, WLC_GET_WEP_RESTRICT, WLC_SET_WEP_RESTRICT,
	"Drop unencrypted packets if WSEC is enabled\n"
	"\t0 - disable\n"
	"\t1 - enable" },
	{ "eap", wl_int, WLC_GET_EAP_RESTRICT, WLC_SET_EAP_RESTRICT,
	"restrict traffic to 802.1X packets until 802.1X authorization succeeds\n"
	"\t0 - disable\n"
	"\t1 - enable" },
	{ "authorize", wl_mac, -1, WLC_SCB_AUTHORIZE,
	"restrict traffic to 802.1X packets until 802.1X authorization succeeds" },
	{ "deauthorize", wl_mac, -1, WLC_SCB_DEAUTHORIZE,
	"do not restrict traffic to 802.1X packets until 802.1X authorization succeeds" },
	{ "deauthenticate", wl_deauth_rc, -1, WLC_SCB_DEAUTHENTICATE_FOR_REASON,
	"deauthenticate a STA from the AP with optional reason code (AP ONLY)" },
	{ "wsec", wl_wsec, WLC_GET_WSEC, WLC_SET_WSEC,
	"wireless security bit vector\n"
	"\t1 - WEP enabled\n"
	"\t2 - TKIP enabled\n"
	"\t4 - AES enabled\n"
	"\t8 - WSEC in software\n"
	"\t0x80 - FIPS enabled" },
	{ "auth", wl_bsscfg_int, WLC_GET_AUTH, WLC_SET_AUTH,
	"set/get 802.11 authentication type. 0 = OpenSystem, 1= SharedKey" },
	{ "wpa_auth", wl_wpa_auth, WLC_GET_WPA_AUTH, WLC_SET_WPA_AUTH,
	"Bitvector of WPA authorization modes:\n"
	"\t1	WPA-NONE\n"
	"\t2	WPA-802.1X/WPA-Professional\n"
	"\t4	WPA-PSK/WPA-Personal\n"
#ifdef BCMWPA2
	"\t64	WPA2-802.1X/WPA2-Professional\n"
	"\t128	WPA2-PSK/WPA2-Personal\n"
#endif /* BCMWPA2 */
	"\t0	disable WPA"
	},
	{ "wpa_cap", wl_bsscfg_int, WLC_GET_VAR, WLC_SET_VAR,
	"set/get 802.11i RSN capabilities" },
	{ "set_pmk", wl_set_pmk, -1, WLC_SET_WSEC_PMK,
	"Set passphrase for PMK in driver-resident supplicant." },
	{ "scan", wl_scan, -1, WLC_SCAN,
	"Initiate a scan.\n"
	"\tDefault an active scan across all channels for any SSID.\n"
	"\tOptional arg: SSID, the SSID to scan.\n"
	"\tOptions:\n"
	"\t-s S, --ssid=S\t\tSSID to scan\n"
	"\t-t ST, --scan_type=ST\t[active|passive] scan type\n"
	"\t--bss_type=BT\t\t[bss/infra|ibss/adhoc] bss type to scan\n"
	"\t-b MAC, --bssid=MAC\tparticular BSSID MAC address to scan, xx:xx:xx:xx:xx:xx\n"
	"\t-n N, --nprobes=N\tnumber of probes per scanned channel\n"
	"\t-a N, --active=N\tdwell time per channel for active scanning\n"
	"\t-p N, --passive=N\tdwell time per channel for passive scanning\n"
	"\t-h N, --home=N\t\tdwell time for the home channel between channel scans\n"
	"\t-c L, --channels=L\tcomma or space separated list of channels to scan"},
	{ "passive", wl_int, WLC_GET_PASSIVE_SCAN, WLC_SET_PASSIVE_SCAN,
	"Puts scan engine into passive mode" },
	{ "regulatory", wl_int, WLC_GET_REGULATORY, WLC_SET_REGULATORY,
	"Get/Set regulatory domain mode (802.11d). Driver must be down." },
	{ "spect", wl_spect, WLC_GET_SPECT_MANAGMENT, WLC_SET_SPECT_MANAGMENT,
	"Get/Set 802.11h Spectrum Management mode.\n"
	"\t0 - Off\n"
	"\t1 - Loose interpretation of 11h spec - may join non-11h APs\n"
	"\t2 - Strict interpretation of 11h spec - may not join non-11h APs\n"
	"\t3 - Disable 11h and enable 11d\n"
	"\t4 - Loose interpretation of 11h+d spec - may join non-11h APs"
	},
	{ "scanresults", wl_dump_networks, WLC_SCAN_RESULTS, -1,
	"Return results from last scan." },
	{ "assoc",  wl_status, -1, -1,
	"Print information about current network association.\n"
	"\t(also known as \"status\")" },
	{ "status", wl_status, -1, -1,
	"Print information about current network association.\n"
	"\t(also known as \"assoc\")" },
	{ "disassoc", wl_void, -1, WLC_DISASSOC,
	"Disassociate from the current BSS/IBSS." },
	{ "chanlist", wl_print_deprecate, WLC_GET_VALID_CHANNELS, -1,
	"Deprecated. Use channels." },
	{ "channels", wl_dump_chanlist, WLC_GET_VALID_CHANNELS, -1,
	"Return valid channels for the current settings." },
	{ "channels_in_country", wl_channels_in_country, WLC_GET_CHANNELS_IN_COUNTRY, -1,
	"Return valid channels for the country specified.\n"
	"\tArg 1 is the country abbreviation\n"
	"\tArg 2 is the band(a or b)"},
	{ "curpower", wl_get_current_power, WLC_CURRENT_PWR, -1,
	"Return current tx power settings.\n"
	"\t-q (quiet): estimated power only." },
	{ "txinstpwr", wl_get_instant_power, WLC_GET_VAR, -1,
	"Return tx power based on instant TSSI "},
	{ "scansuppress", wl_int, WLC_GET_SCANSUPPRESS, WLC_SET_SCANSUPPRESS,
	"Suppress all scans for testing.\n"
	"\t0 - allow scans\n"
	"\t1 - suppress scans" },
	{ "evm", wl_evm, -1, WLC_EVM,
	"Start an EVM test on the given channel, or stop EVM test.\n"
	"\tArg 1 is channel number 1-14, or \"off\" or 0 to stop the test.\n"
	"\tArg 2 is optional rate (1, 2, 5.5 or 11)"},
	{ "rateset", wl_rateset, WLC_GET_RATESET, WLC_SET_RATESET,
	"Returns or sets the supported and basic rateset, (b) indicates basic\n"
	"\tWith no args, returns the rateset. Args are\n"
	"\trateset \"default\" | \"all\" | <arbitrary rateset>\n"
	"\t\tdefault - driver defaults\n"
	"\t\tall - all rates are basic rates\n"
	"\t\tarbitrary rateset - list of rates\n"
	"\tList of rates are in Mbps and each rate is optionally followed\n"
	"\tby \"(b)\" or \"b\" for a Basic rate. Example: 1(b) 2b 5.5 11\n"
	"\tAt least one rate must be Basic for a legal rateset."},
	{ "roam_trigger", wl_band_elm, WLC_GET_ROAM_TRIGGER, WLC_SET_ROAM_TRIGGER,
	"Get or Set the roam trigger RSSI threshold:\n"
	"\tGet: roam_trigger [a|b]\n"
	"\tSet: roam_trigger <integer> [a|b|all]\n"
	"\tinteger -   0: default\n"
	"\t            1: optimize bandwidth\n"
	"\t            2: optimize distance\n"
	"\t    [-1, -99]: dBm trigger value"},
	{ "roam_delta",	wl_band_elm, WLC_GET_ROAM_DELTA, WLC_SET_ROAM_DELTA,
	"Set the roam candidate qualification delta. roam_delta [integer [, a/b]]" },
	{ "roam_scan_period", wl_int, WLC_GET_ROAM_SCAN_PERIOD, WLC_SET_ROAM_SCAN_PERIOD,
	"Set the roam candidate qualification delta.  (integer)" },
	{ "suprates", wl_sup_rateset, WLC_GET_SUP_RATESET_OVERRIDE, WLC_SET_SUP_RATESET_OVERRIDE,
	"Returns or sets the 11g override for the supported rateset\n"
	"\tWith no args, returns the rateset. Args are a list of rates,\n"
	"\tor 0 or -1 to specify an empty rateset to clear the override.\n"
	"\tList of rates are in Mbps, example: 1 2 5.5 11"},
	{ "scan_channel_time", wl_int, WLC_GET_SCAN_CHANNEL_TIME, WLC_SET_SCAN_CHANNEL_TIME,
	"Get/Set scan channel time"},
	{ "scan_unassoc_time", wl_int, WLC_GET_SCAN_UNASSOC_TIME, WLC_SET_SCAN_UNASSOC_TIME,
	"Get/Set unassociated scan channel dwell time"},
	{ "scan_home_time", wl_int, WLC_GET_SCAN_HOME_TIME, WLC_SET_SCAN_HOME_TIME,
	"Get/Set scan home channel dwell time"},
	{ "scan_passive_time", wl_int, WLC_GET_SCAN_PASSIVE_TIME, WLC_SET_SCAN_PASSIVE_TIME,
	"Get/Set passive scan channel dwell time"},
	{ "scan_nprobes", wl_int, WLC_GET_SCAN_NPROBES, WLC_SET_SCAN_NPROBES,
	"Get/Set scan parameter for number of probes to use per channel scanned"},
	{ "prb_resp_timeout", wl_int, WLC_GET_PRB_RESP_TIMEOUT, WLC_SET_PRB_RESP_TIMEOUT,
	"Get/Set probe response timeout"},
	{ "channel_qa", wl_int, WLC_GET_CHANNEL_QA, -1,
	"Get last channel quality measurment"},
	{ "channel_qa_start", wl_void, -1, WLC_START_CHANNEL_QA,
	"Start a channel quality measurment"},
	{ "country", wl_country, WLC_GET_COUNTRY, WLC_SET_COUNTRY,
	"Select Country Code for driver operational region\n"
	"\tUse either long name or abbreviation from ISO 3166.\n"
	"\tUse 'wl country list [band(a or b)]' for the list of supported countries"},
	{ "autocountry_default", wl_varstr, WLC_GET_VAR, WLC_SET_VAR,
	"Select Country Code for use with Auto Contry Discovery"},
	{ "join", wl_join, -1, -1,
	"Join a specified network SSID.\n"
	"\tJoin syntax is: join <ssid> [key xxxxx] [imode bss|ibss] "
	"[amode open|shared|wpa|wpapsk|wpa2|wpa2psk|wpanone]"},
	{ "ssid", wl_ssid, WLC_GET_SSID, WLC_SET_SSID,
	"Set or get a configuration's SSID.\n"
	"\twl ssid [-C num]|[--cfg=num] [<ssid>]\n"
	"\tIf the configuration index 'num' is not given, configuraion #0 is assumed and\n"
	"\tsetting will initiate an assoication attempt if in infrastructure mode,\n"
	"\tor join/creation of an IBSS if in IBSS mode,\n"
	"\tor creation of a BSS if in AP mode."},
	{ "mac", wl_maclist, WLC_GET_MACLIST, WLC_SET_MACLIST,
	"Set or get the list of source MAC address matches.\n"
	"\twl mac xx:xx:xx:xx:xx:xx [xx:xx:xx:xx:xx:xx ...]\n"
	"\tTo Clear the list: wl mac none" },
	{ "macmode", wl_int, WLC_GET_MACMODE, WLC_SET_MACMODE,
	"Set the mode of the MAC list.\n"
	"\t0 - Disable MAC address matching.\n"
	"\t1 - Deny association to stations on the MAC list.\n"
	"\t2 - Allow association to stations on the MAC list."},
	{ "wds", wl_maclist, WLC_GET_WDSLIST, WLC_SET_WDSLIST,
	"Set or get the list of WDS member MAC addresses.\n"
	"\tSet using a space separated list of MAC addresses.\n"
	"\t wl wds xx:xx:xx:xx:xx:xx [xx:xx:xx:xx:xx:xx ...]" },
	{ "lazywds", wl_int, WLC_GET_LAZYWDS, WLC_SET_LAZYWDS,
	"Set or get \"lazy\" WDS mode (dynamically grant WDS membership to anyone)."},
	{ "noise", wl_int, WLC_GET_PHY_NOISE, -1,
	"Get noise (moving average) right after tx in dBm" },
	{ "fqacurcy", wl_int, -1, WLC_FREQ_ACCURACY,
	"Manufacturing test: set frequency accuracy mode.\n"
	"\tfreqacuracy syntax is: fqacurcy <channel>\n"
	"\tArg is channel number 1-14, or 0 to stop the test." },
	{ "crsuprs", wl_int, -1, WLC_CARRIER_SUPPRESS,
	"Manufacturing test: set carrier suppression mode.\n"
	"\tcarriersuprs syntax is: crsuprs <channel>\n"
	"\tArg is channel number 1-14, or 0 to stop the test." },
	{ "longtrain", wl_int, -1, WLC_LONGTRAIN,
	"Manufacturing test: set longtraining mode.\n"
	"\tlongtrain syntax is: longtrain <channel>\n"
	"\tArg is A band channel number or 0 to stop the test." },
	{ "band", wl_band, WLC_GET_BAND, WLC_SET_BAND,
	"Returns or sets the current band\n"
	"\tauto - auto switch between available bands (default)\n"
	"\ta - force use of 802.11a band\n"
	"\tb - force use of 802.11b band" },
	{ "bands", wl_bandlist, WLC_GET_BANDLIST, -1,
	"Return the list of available 802.11 bands" },
	{ "phylist", wl_phylist, WLC_GET_PHYLIST, -1,
	"Return the list of available phytypes" },
	{ "shortslot", wl_int, WLC_GET_SHORTSLOT, -1,
	"Get current 11g Short Slot Timing mode. (0=long, 1=short)" },
	{ "shortslot_override", wl_int, WLC_GET_SHORTSLOT_OVERRIDE, WLC_SET_SHORTSLOT_OVERRIDE,
	"Get/Set 11g Short Slot Timing mode override. (-1=auto, 0=long, 1=short)" },
	{ "shortslot_restrict", wl_int, WLC_GET_SHORTSLOT_RESTRICT, WLC_SET_SHORTSLOT_RESTRICT,
	"Get/Set AP Restriction on associations for 11g Short Slot Timing capable STAs.\n"
	"\t0 - Do not restrict association based on ShortSlot capability\n"
	"\t1 - Restrict association to STAs with ShortSlot capability" },
	{ "ignore_bcns", wl_int, WLC_GET_IGNORE_BCNS, WLC_SET_IGNORE_BCNS,
	"AP only (G mode): Check for beacons without NONERP element"
	"(0=Examine beacons, 1=Ignore beacons)" },
	{ "pktcnt", wl_get_pktcnt, WLC_GET_PKTCNTS, -1,
	"Get the summary of good and bad packets." },
	{ "upgrade", wl_upgrade, -1, WLC_UPGRADE,
	"Upgrade the firmware on an embedded device" },
	{ "gmode", wl_gmode, WLC_GET_GMODE, WLC_SET_GMODE,
	"Set the 54g Mode (LegacyB|Auto||GOnly|BDeferred|Performance|LRS)" },
	{ "gmode_protection", wl_int, WLC_GET_GMODE_PROTECTION, -1,
	"Get G protection mode. (0=disabled, 1=enabled)" },
	{ "gmode_protection_control", wl_int, WLC_GET_GMODE_PROTECTION_CONTROL,
	WLC_SET_GMODE_PROTECTION_CONTROL,
	"Get/Set 11g protection mode control alg."
	"(0=always off, 1=monitor local association, 2=monitor overlapping BSS)" },
	{ "gmode_protection_override", wl_int, WLC_GET_GMODE_PROTECTION_OVERRIDE,
	WLC_SET_GMODE_PROTECTION_OVERRIDE,
	"Get/Set 11g protection mode override. (-1=auto, 0=disable, 1=enable)" },
	{ "protection_control", wl_int, WLC_GET_PROTECTION_CONTROL,
	WLC_SET_PROTECTION_CONTROL,
	"Get/Set protection mode control alg."
	"(0=always off, 1=monitor local association, 2=monitor overlapping BSS)" },
	{ "legacy_erp", wl_int, WLC_GET_LEGACY_ERP, WLC_SET_LEGACY_ERP,
	"Get/Set 11g legacy ERP inclusion (0=disable, 1=enable)" },
	{ "scb_timeout", wl_int, WLC_GET_SCB_TIMEOUT, WLC_SET_SCB_TIMEOUT,
	"AP only: inactivity timeout value for authenticated stas" },
	{ "assoclist", wl_maclist, WLC_GET_ASSOCLIST, -1,
	"AP only: Get the list of associated MAC addresses."},
	{ "isup", wl_int, WLC_GET_UP, -1,
	"Get driver operational state (0=down, 1=up)"},
	{ "rssi", wl_rssi, WLC_GET_RSSI, -1,
	"Get the current RSSI val, for an AP you must specify the mac addr of the STA" },
	{ "phy_rssi_ant", wl_phy_rssi_ant, WLC_GET_VAR, WLC_SET_VAR,
	"Get RSSI per antenna (only support NPHY now)\n"},
	{ "fasttimer", wl_print_deprecate, -1, -1,
	"Deprecated. Use fast_timer."},
	{ "slowtimer", wl_print_deprecate, -1, -1,
	"Deprecated. Use slow_timer."},
	{ "glacialtimer", wl_print_deprecate, -1, -1,
	"Deprecated. Use glacial_timer."},
	{ "radar", wl_int, WLC_GET_RADAR, WLC_SET_RADAR,
	"Enable/Disable radar"},
	{ "radarargs", wl_radar_args, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set Radar parameters in \n"
	"\torder as npulses, ncontig, min_pw , max_pw, thresh0, thresh1, \n"
	"\tnpulses_lp, min_pw_lp, max_pw_lp, min_fm_lp, max_deltat_lp, min_deltat\n"},
	{ "radarargs40", wl_radar_args, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set Radar parameters for 40Mhz channel in \n"
	"\torder as npulses, ncontig, min_pw , max_pw, thresh0, thresh1, \n"
	"\tnpulses_lp, min_pw_lp, max_pw_lp, min_fm_lp, max_deltat_lp, min_deltat\n"},
	{ "dfs_status", wl_dfs_status, WLC_GET_VAR, -1,
	"Get dfs status"},
	{ "interference", wl_interfere, WLC_GET_INTERFERENCE_MODE, WLC_SET_INTERFERENCE_MODE,
	"Get/Set interference mitigation mode. Choices are:\n"
	"\t0 = none\n"
	"\t1 = non wlan\n"
	"\t2 = wlan manual\n"
	"\t3 = wlan automatic"},
	{ "frameburst", wl_int, WLC_GET_FAKEFRAG, WLC_SET_FAKEFRAG,
	"Disable/Enable frameburst mode" },
	{ "pwr_percent", wl_int, WLC_GET_PWROUT_PERCENTAGE, WLC_SET_PWROUT_PERCENTAGE,
	"Get/Set power output percentage"},
	{ "wet", wl_int, WLC_GET_WET, WLC_SET_WET,
	"Get/Set wireless ethernet bridging mode"},
	{ "bi", wl_int, WLC_GET_BCNPRD, WLC_SET_BCNPRD,
	"Get/Set the beacon period (bi=beacon interval)"},
	{ "dtim", wl_int, WLC_GET_DTIMPRD, WLC_SET_DTIMPRD,
	"Get/Set DTIM"},
	{ "wds_remote_mac", wl_mac, WLC_WDS_GET_REMOTE_HWADDR, -1,
	"Get WDS link remote endpoint's MAC address"},
	{ "wds_wpa_role_old", wl_wds_wpa_role_old, WLC_WDS_GET_WPA_SUP, -1,
	"Get WDS link local endpoint's WPA role (old)"},
	{ "wds_wpa_role", wl_wds_wpa_role, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set WDS link local endpoint's WPA role"},
	{ "authe_sta_list", wl_maclist_1, WLC_GET_VAR, -1,
	"Get authenticated sta mac address list"},
	{ "autho_sta_list", wl_maclist_1, WLC_GET_VAR, -1,
	"Get authorized sta mac address list"},
	{ "measure_req", wl_measure_req, -1, WLC_MEASURE_REQUEST,
	"Send an 802.11h measurement request.\n"
	"\tUsage: wl measure_req <type> <target MAC addr>\n"
	"\tMeasurement types are: TPC, Basic, CCA, RPI\n"
	"\tTarget MAC addr format is xx:xx:xx:xx:xx:xx"},
	{ "quiet", wl_send_quiet, -1, WLC_SEND_QUIET,
	"Send an 802.11h quiet command.\n"
	"\tUsage: wl quiet <TBTTs until start>, <duration (in TUs)>, <offset (in TUs)>"},
	{ "csa", wl_send_csa, -1, WLC_SET_VAR,
	"Send an 802.11h channel switch anouncement with chanspec:\n"
	"\t<mode> <count> <channel>[a,b][n][u,l]\n"
	"\tmode (0 or 1)\n"
	"\tcount (0-254)\n"
	"\tchannel number (0-224)\n"
	"\tband a=5G, b=2G\n"
	"\tbandwidth n=10, non for 20 & 40\n"
	"\tctl sideband, l=lower, u=upper, default no ctl sideband\n"},
	{ "constraint", wl_int, -1, WLC_SEND_PWR_CONSTRAINT,
	"Send an 802.11h Power Constraint IE\n"
	"\tUsage: wl constraint 1-255 db"},
	{ "rm_req", wl_rm_request, -1, WLC_SET_VAR,
	"Request a radio measurement of type basic, cca, or rpi\n"
	"\tspecify a series of measurement types each followed by options.\n"
	"\texample: wl rm_req cca -c 1 -d 50 cca -c 6 cca -c 11\n"
	"\tOptions:\n"
	"\t-t n  numeric token id for measurement set or measurement\n"
	"\t-c n  channel\n"
	"\t-d n  duration in TUs (1024 us)\n"
	"\t-p    parallel flag, measurement starts at the same time as previous\n"
	"\n"
	"\tEach measurement specified uses the same channel and duration as the\n"
	"\tprevious unless a new channel or duration is specified."},
	{ "rm_rep", wl_rm_report, WLC_GET_VAR, -1,
	"Get current radio measurement report"},
	{ "join_pref", wl_join_pref, WLC_GET_VAR, WLC_SET_VAR,
	"Set/Get join target preferences."},
	{ "assoc_pref", wl_assoc_pref, WLC_GET_ASSOC_PREFER, WLC_SET_ASSOC_PREFER,
	"Set/Get association preference.\n"
	"Usage: wl assoc_pref [auto|a|b|g]"},
	{ "wme", wl_varint, WLC_GET_VAR, WLC_SET_VAR,
	"Set WME (Wireless Multimedia Extensions) mode (0=off, 1=on, -1=auto)"},
	{ "wme_ac", wl_wme_ac_req, WLC_GET_VAR, WLC_SET_VAR,
	"wl wme_ac ap|sta [be|bk|vi|vo [ecwmax|ecwmin|txop|aifsn|acm <value>] ...]"},
	{ "wme_apsd", wl_varint, WLC_GET_VAR, WLC_SET_VAR,
	"Set APSD (Automatic Power Save Delivery) mode on AP (0=off, 1=on)" },
	{ "wme_apsd_sta", wl_wme_apsd_sta, WLC_GET_VAR, WLC_SET_VAR,
	"Set APSD parameters on STA. Driver must be down.\n"
	"Usage: wl wme_apsd_sta <max_sp_len> <be> <bk> <vi> <vo>\n"
	"   <max_sp_len>: number of frames per USP: 0 (all), 2, 4, or 6\n"
	"   <xx>: value 0 to disable, 1 to enable U-APSD per AC" },
	{ "wme_dp", wl_wme_dp, WLC_GET_VAR, WLC_SET_VAR,
	"Set AC queue discard policy.\n"
	"Usage: wl wme_dp <be> <bk> <vi> <vo>\n"
	"   <xx>: value 0 for newest-first, 1 for oldest-first" },
	{ "wme_counters", wl_wme_counters, WLC_GET_VAR, -1,
	"print WMM stats" },
	{ "wme_clear_counters", wl_var_void, -1, WLC_SET_VAR,
	"clear WMM counters"},
	{ "lifetime", wl_lifetime, WLC_GET_VAR, WLC_SET_VAR,
	"Set Lifetime parameter (milliseconds) for each ac.\n"
	"wl lifetime be|bk|vi|vo [<value>]"},
	{ "reinit", wl_void, -1, WLC_INIT,
	"Reinitialize device"},
	{ "sta_info", wl_sta_info, WLC_GET_VAR, -1,
	"wl sta_info <xx:xx:xx:xx:xx:xx>"},
	{ "nphy_test_tssi", wl_test_tssi, WLC_GET_VAR, -1,
	"wl nphy_test_tssi val"},
	{ "nphy_test_tssi_offs", wl_test_tssi_offs, WLC_GET_VAR, -1,
	"wl nphy_test_tssi_offs val"},
	{ "cap", wl_var_getandprintstr, WLC_GET_VAR, -1, "driver capabilities"},
	{ "malloc_dump", wl_print_deprecate, -1, -1, "Deprecated. Folded under 'wl dump malloc"},
	{ "chan_info", wl_chan_info, WLC_GET_VAR, -1, "channel info"},
	{ "add_ie", wl_add_ie, -1, WLC_SET_VAR,
	"Add a vendor proprietary IE to 802.11 management packets\n"
	"Usage: wl add_ie <pktflag> length OUI hexdata\n"
	"<pktflag>: Bit 0 - Beacons\n"
	"           Bit 1 - Probe Rsp\n"
	"           Bit 2 - Assoc/Reassoc Rsp\n"
	"           Bit 3 - Auth Rsp\n"
	"           Bit 4 - Probe Req\n"
	"           Bit 5 - Assoc/Reassoc Req\n"
	"Example: wl add_ie 3 10 00:90:4C 0101050c121a03\n"
	"         to add this IE to beacons and probe responses" },
	{ "del_ie", wl_del_ie, -1, WLC_SET_VAR,
	"Delete a vendor proprietary IE from 802.11 management packets\n"
	"Usage: wl del_ie <pktflag> length OUI hexdata\n"
	"<pktflag>: Bit 0 - Beacons\n"
	"           Bit 1 - Probe Rsp\n"
	"           Bit 2 - Assoc/Reassoc Rsp\n"
	"           Bit 3 - Auth Rsp\n"
	"           Bit 4 - Probe Req\n"
	"           Bit 5 - Assoc/Reassoc Req\n"
	"Example: wl del_ie 3 10 00:90:4C 0101050c121a03" },
	{ "list_ie", wl_list_ie, WLC_GET_VAR, -1,
	"Dump the list of vendor proprietary IEs" },
	{ "rand", wl_rand, WLC_GET_VAR, -1,
	"Get a 2-byte Random Number from the MAC's PRNG\n"
	"Usage: wl rand"},
	{ "otpw", wl_otpw, -1, WLC_OTPW,
	"Write an srom image to on-chip otp\n"
	"Usage: wl otpw file"},
	{ "nvotpw", wl_otpw, -1, WLC_NVOTPW,
	"Write nvram to on-chip otp\n"
	"Usage: wl nvotpw file"},
	{ "bcmerrorstr", wl_var_getandprintstr, WLC_GET_VAR, -1, "errorstring"},
	{ "freqtrack", wl_varint, WLC_GET_VAR, WLC_SET_VAR,
	"Set Frequency Tracking Mode (0=Auto, 1=On, 2=OFF)"},
	{ "eventing", wl_bitvec128, WLC_GET_VAR, WLC_SET_VAR,
	"set/get 128-bit hex filter bitmask for MAC event reporting up to application layer"},
	{ "event_msgs", wl_bitvec128, WLC_GET_VAR, WLC_SET_VAR,
	"set/get 128-bit hex filter bitmask for MAC event reporting via packet indications"},
	{ "counters", wl_counters, WLC_GET_VAR, -1,
	"Return driver counter values" },
	{ "assoc_info", wl_assoc_info, WLC_GET_VAR, -1,
	"Returns the assoc req and resp information [STA only]" },
	{ "autochannel", wl_auto_channel_sel, WLC_GET_CHANNEL_SEL, WLC_START_CHANNEL_SEL,
	"auto channel selection: \n"
	"\t1 to issue a channel scanning;\n"
	"\t2 to set channel based on the channel scanning result;\n"
	"\twithout argument to only show the channel selected; \n"
	"\tssid must set to null before this process, RF must be up"},
	{ "csscantimer", wl_int, WLC_GET_CS_SCAN_TIMER, WLC_SET_CS_SCAN_TIMER,
	"auto channel scan timer in minutes (0 to disable)" },
	{ "closed", wl_int, WLC_GET_CLOSED, WLC_SET_CLOSED,
	"hides the network from active scans, 0 or 1.\n"
	"\t0 is open, 1 is hide" },
#ifdef BCMWPA2
	{ "pmkid_info", wl_pmkid_info, WLC_GET_VAR, WLC_SET_VAR,
	"Returns the pmkid table" },
#endif /* BCMWPA2 */
	{ "abminrate", wl_phy_rate, WLC_GET_VAR, WLC_SET_VAR,
	"get/set afterburner minimum rate threshold" },
	{ "bss", wl_bsscfg_enable, WLC_GET_VAR, WLC_SET_VAR,
	"set/get BSS enabled status: up/down"},
	{ "closednet", wl_bsscfg_int, WLC_GET_VAR, WLC_SET_VAR,
	"set/get BSS closed network attribute"},
	{ "ap_isolate", wl_bsscfg_int, WLC_GET_VAR, WLC_SET_VAR,
	"set/get AP isolation"},
	{ "eap_restrict", wl_bsscfg_int, WLC_GET_VAR, WLC_SET_VAR,
	"set/get EAP restriction"},
	{ "diag", wl_diag, WLC_GET_VAR, -1,
	"diag testindex(1-interrupt, 2-loopback, 3-memory, 4-led);"
	" precede by 'wl down' and follow by 'wl up'" },
	{ "reset_d11cnts", wl_var_void, -1, WLC_SET_VAR,
	"reset 802.11 MIB counters"},
	{ "staname", wl_varstr, WLC_GET_VAR, WLC_SET_VAR,
	"get/set station name: \n"
	"\tMaximum name length is 15 bytes"},
	{ "apname", wl_varstr, WLC_GET_VAR, -1,
	"get AP name"},
	{ "otpdump", wl_var_setintandprintstr, WLC_GET_VAR, -1,
	"Dump raw otp"},
	{ "nrate", wl_nrate, WLC_GET_VAR, WLC_SET_VAR,
	"-r legacy rate (CCK, OFDM)"
	"-m mcs index"
	"-s stf mode (0=SISO,1=CDD,2=STBC(not supported),3=SDM)"},
	{ "mimo_txbw", wl_varint, WLC_GET_VAR, WLC_SET_VAR,
	"get/set mimo txbw (2=20Mhz(lower), 3=20Mhz upper, 4=40Mhz, 5=40Mhz dup<mcs32 only)"},

	{ "cac_addts", wl_cac, -1, WLC_SET_VAR,
	"add TSPEC, error if STA is not associated or WME is not enabled"},
	{ "cac_delts", wl_cac, -1, WLC_SET_VAR,
	"delete TSPEC, error if STA is not associated or WME is not enabled"},
	{ "cac_tslist", wl_tslist, WLC_GET_VAR, -1,
	"Get the list of TSINFO in driver\n"
	"\teg. 'wl cac_tslist' get a list of TSINFO"},
	{ "cac_tspec", wl_tspec, WLC_GET_VAR, -1,
	"Get specific TSPEC with matching TSINFO\n"
	"\teg. 'wl cac_tspec 0xaa 0xbb 0xcc' where 0xaa 0xbb & 0xcc are TSINFO octets"},

	{ "nphy_caldump", wl_caldump, WLC_GET_VAR, -1,
	"Dump the NPHY calibration coefficients" },
	{ "nphy_antsel", wl_antsel, WLC_GET_VAR, -1,
	"get/set antenna configuration \n"
	"\tset: -1(AUTO), 0xAB(fixed antenna selection)\n"
	"\t\twhere A and B is the antenna numbers used for RF chain 0 and 1 respectively\n"
	"\tquery: <utx>[AUTO] <urx>[AUTO] <dtx>[AUTO] <drx>[AUTO]\n"
	"\t\twhere utx = TX unicast antenna configuration\n"
	"\t\t\turx = RX unicast antenna configuration\n"
	"\t\t\tdtx = TX default (non-unicast) antenna configuration\n"
	"\t\t\tdrx = RX default (non-unicast) antenna configuration\n"
	},
	{ "txfifo_sz", wl_txfifo_sz, WLC_GET_VAR, WLC_SET_VAR,
	"set/get the txfifo size; usage: wl txfifo_sz <fifonum> <size_in_bytes>" },
#ifdef DSLCPE
	{ "assoclistinfo", wl_assoclist_info, -1, -1,
	"AP only: Get the list of yet another form of associated station info" },
#endif	
	{ NULL, NULL, 0, 0, NULL }
};

cmd_t wl_varcmd = {"var", wl_varint, -1, -1, "unrecognized name, type -h for help"};
const char *av0 = "";

#ifdef WC_TOOL
/* Include any commands for wc tool used for WMM
 * These need to be only the command names from port_cmds and wl_cmds array
 */
static const char *wc_cmds[] = {
	"ver", "cmds", "up", "down",
	"gmode", "listen", "wme", "wme_ac", "wme_apsd",
	"wme_apsd_sta", "wme_dp"
};
#else
static const char **wc_cmds = NULL;
#endif /* WC_TOOL */

/* initialize stuff needed before processing the command */
void
wl_cmd_init(void)
{
	int_fmt = INT_FMT_DEC;
}

/* parse/validate the command line arguments */
/*
* pargv is updated upon return if the first argument is an option.
 * It remains intact otherwise.
 */
int
wl_option(char ***pargv, char **pifname, int *phelp)
{
	char *ifname = NULL;
	int help = FALSE;
	int status = CMD_OPT;
	char **argv = *pargv;

	while (*argv) {
		/* select different adapter */
		if (!strcmp(*argv, "-a") || !strcmp(*argv, "-i")) {
			char *opt = *argv++;
			ifname = *argv;
			if (!ifname) {
				fprintf(stderr,
					"error: expected interface name after option %s\n", opt);
				status = CMD_ERR;
				break;
			}
		}

		/* integer output format */
		else if (!strcmp(*argv, "-d"))
			int_fmt = INT_FMT_DEC;
		else if (!strcmp(*argv, "-u"))
			int_fmt = INT_FMT_UINT;
		else if (!strcmp(*argv, "-x"))
			int_fmt = INT_FMT_HEX;

		/* command usage */
		else if (!strcmp(*argv, "-h"))
			help = TRUE;

		/* start of non wl options */
		else {
			status = CMD_WL;
			break;
		}

		/* consume the argument */
		argv ++;
		break;
	}

	*phelp = help;
	*pifname = ifname;
	*pargv = argv;

	return status;
}

void
cmd_usage(FILE *fid, cmd_t *cmd)
{
	if (strlen(cmd->name) >= 8)
		fprintf(fid, "%s\n\t%s\n\n", cmd->name, cmd->help);
	else
		fprintf(fid, "%s\t%s\n\n", cmd->name, cmd->help);
}

static int
wl_print_deprecate(void *wl, cmd_t *cmd, char **argv)
{
	cmd_usage(stderr, cmd); /* warning string is in command table */
	return 0;
}

/* Dump out short list of commands */
static int
wl_list(void *wl, cmd_t *garb, char **argv)
{
	cmd_t *cmd;
	int nrows, i, len;
	char *list_buf;
	int letter, col, row, pad;

	for (cmd = wl_cmds, nrows = 0; cmd->name; cmd++)
		/* Check for wc_cmd */
		if (wc_cmd_check(cmd->name))
		    nrows++;

	nrows /= 4;
	nrows++;

	len = nrows * 80 + 2;
	list_buf = malloc(len);
	if (list_buf == NULL) {
		fprintf(stderr, "Failed to allocate buffer of %d bytes\n", len);
		return -1;
	}
	for (i = 0; i < len; i++)
		*(list_buf+i) = 0;

	row = col = 0;
	for (letter = 'a'; letter < 'z'; letter++) {
		for (cmd = wl_cmds; cmd->name; cmd++) {
			/* Check for wc_cmd */
			if (!wc_cmd_check(cmd->name))
				continue;
			if (cmd->name[0] == letter || cmd->name[0] == letter - 0x20) {
				strcat(list_buf+row*80, cmd->name);
				pad = 18 * (col + 1) - strlen(list_buf+row*80);
				if (pad < 1)
					pad = 1;
				for (; pad; pad--)
					strcat(list_buf+row*80, " ");
				row++;
				if (row == nrows) {
					col++; row = 0;
				}
			}
		}
	}
	for (row = 0; row < nrows; row++)
		printf("%s\n", list_buf+row*80);

	printf("\n");
	return (0);
}

void
wl_cmds_usage(FILE *fid, cmd_t *port_cmds)
{
	cmd_t *port_cmd;
	cmd_t *cmd;

	/* print usage of port commands */
	for (port_cmd = port_cmds; port_cmd && port_cmd->name; port_cmd++)
		/* Check for wc_cmd */
		if (wc_cmd_check(port_cmd->name))
			cmd_usage(fid, port_cmd);

	/* print usage of common commands without port counterparts */
	for (cmd = wl_cmds; cmd->name; cmd++) {
		/* search if port counterpart exists */
		for (port_cmd = port_cmds; port_cmd && port_cmd->name; port_cmd++)
			if (!strcmp(port_cmd->name, cmd->name))
				break;
		/* Also, check for this being a wc_cmd */
		if ((!port_cmd || !port_cmd->name) && (wc_cmd_check(cmd->name)))
			cmd_usage(fid, cmd);
	}
}

void
wl_usage(FILE *fid, cmd_t *port_cmds)
{
	fprintf(fid, "Usage: %s [-a|i <adapter>] [-h] [-d|u|x] <command> [arguments]\n", av0);

	fprintf(fid, "\n");
	fprintf(fid, "  -h        this message and command descriptions\n");
	fprintf(fid, "  -h [cmd]  command description for cmd\n");
	fprintf(fid, "  -a, -i    adapter name or number\n");
	fprintf(fid, "  -d        output format signed integer\n");
	fprintf(fid, "  -u        output format unsigned integer\n");
	fprintf(fid, "  -x        output format hexdecimal\n");
	fprintf(fid, "\n");

	wl_cmds_usage(fid, port_cmds);
}

int
wl_check(void *wl)
{
	int ret;
	int val;

	if ((ret = wl_get(wl, WLC_GET_MAGIC, &val, sizeof(int)) < 0))
		return ret;
	if (val != WLC_IOCTL_MAGIC)
		return -1;
	if ((ret = wl_get(wl, WLC_GET_VERSION, &val, sizeof(int)) < 0))
		return ret;
	if (val > WLC_IOCTL_VERSION) {
		fprintf(stderr, "Version mismatch, please upgrade\n");
		return -1;
	}
	return 0;
}

void
wl_printint(int val)
{
	switch (int_fmt) {
	case INT_FMT_UINT:
		printf("%u\n", val);
		break;
	case INT_FMT_HEX:
		printf("0x%x\n", val);
		break;
	case INT_FMT_DEC:
	default:
		printf("%d\n", val);
		break;
	}
}


/* Common routine to check for an option arg specifying the configuration index.
 * Takes the syntax -C num, --cfg=num, --config=num, or --configuration=num
 * Returns -1 if there is a command line parsing error.
 * Returns 0 if no error, and sets *consumed to the number of argv strings
 * used. Sets *bsscfg_idx to the index to use. Will set *bsscfg_idx to zero if there
 * was no config arg.
 */
static int
wl_cfg_option(char **argv, const char *fn_name, int *bsscfg_idx, int *consumed)
{
	miniopt_t mo;
	int opt_err;

	*bsscfg_idx = 0;
	*consumed = 0;

	miniopt_init(&mo, fn_name, NULL);

	/* process the first option */
	opt_err = miniopt(&mo, argv);

	/* check for no args or end of options */
	if (opt_err == -1)
		return 0;

	/* check for no options, just a positional arg encountered */
	if (mo.positional)
		return 0;

	/* check for error parsing options */
	if (opt_err == 1)
		return -1;

	/* check for -C, --cfg=X, --config=X, --configuration=X */
	if (mo.opt == 'C' ||
	    !strcmp(mo.key, "cfg") ||
	    !strcmp(mo.key, "config") ||
	    !strcmp(mo.key, "configuration")) {
		if (!mo.good_int) {
			fprintf(stderr,
			"%s: could not parse \"%s\" as an integer for the configuartion index\n",
			fn_name, mo.valstr);
			return -1;
		}
		*bsscfg_idx = mo.val;
		*consumed = mo.consumed;
	}

	return 0;
}

static int
wl_void(void *wl, cmd_t *cmd, char **argv)
{
	if (cmd->set < 0)
		return -1;
	return wl_set(wl, cmd->set, NULL, 0);
}

int
wl_int(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int val;
	char *endptr;

	if (!*++argv) {
		if (cmd->get == -1)
			return -1;
		if ((ret = wl_get(wl, cmd->get, &val, sizeof(int))) < 0)
			return ret;

		wl_printint(val);
	} else {
		if (cmd->set == -1)
			return -1;
		if (!stricmp(*argv, "on"))
			val = 1;
		else if (!stricmp(*argv, "off"))
			val = 0;
		else {
			val = strtol(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}
		}

		ret = wl_set(wl, cmd->set, &val, sizeof(int));
	}

	return ret;
}

static int
wl_bsscfg_int(void *wl, cmd_t *cmd, char **argv)
{
	char *endptr;
	char *val_name;
	int bsscfg_idx = 0;
	int val;
	int consumed;
	int ret;

	val_name = *argv++;

	/* parse a bsscfg_idx option if present */
	if ((ret = wl_cfg_option(argv, val_name, &bsscfg_idx, &consumed)) != 0)
		return ret;

	/* handle a bsscfg int with a legacy ioctl */
	if (consumed == 0 && cmd->set != WLC_SET_VAR) {
		/* back up to the orig command and run as an ioctl int */
		argv--;
		return wl_int(wl, cmd, argv);
	}

	argv += consumed;

	if (!*argv) {
		/* This is a GET */
		if (cmd->get == -1)
			return -1;

		if (consumed == 0)
			ret = wl_iovar_getint(wl, val_name, &val);
		else
			ret = wl_bssiovar_getint(wl, val_name, bsscfg_idx, &val);

		if (ret < 0)
			return ret;

		wl_printint(val);
	} else {
		/* This is a SET */
		if (cmd->set == -1)
			return -1;

		if (!stricmp(*argv, "on"))
			val = 1;
		else if (!stricmp(*argv, "off"))
			val = 0;
		else {
			val = strtol(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}
		}

		if (consumed == 0)
			ret = wl_iovar_setint(wl, val_name, val);
		else
			ret = wl_bssiovar_setint(wl, val_name, bsscfg_idx, val);
	}

	return ret;
}

static int
wl_bsscfg_enable(void *wl, cmd_t *cmd, char **argv)
{
	char *endptr;
	const char *val_name = "bss";
	int bsscfg_idx = 0;
	int val;
	int consumed;
	int ret;

	/* skip the command name */
	argv++;

	/* parse a bsscfg_idx option if present */
	if ((ret = wl_cfg_option(argv, val_name, &bsscfg_idx, &consumed)) != 0)
		return ret;

	argv += consumed;

	if (!*argv) {
		ret = wl_iovar_getbuf(wl, val_name, &bsscfg_idx, sizeof(bsscfg_idx),
		                      buf, WLC_IOCTL_MAXLEN);
		if (ret < 0)
			return ret;
		val = *(int*)buf;
		if (val)
			printf("up\n");
		else
			printf("down\n");
		return 0;
	} else {
		struct {
			int cfg;
			int val;
		} bss_setbuf;
		if (!stricmp(*argv, "up"))
			val = 1;
		else if (!stricmp(*argv, "down"))
			val = 0;
		else {
			val = strtol(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}
		}
		bss_setbuf.cfg = bsscfg_idx;
		bss_setbuf.val = val;

		return wl_iovar_set(wl, val_name, &bss_setbuf, sizeof(bss_setbuf));
	}
}

/* Get/Set the gmode config */
static int
wl_gmode(void *wl, cmd_t *cmd, char **argv)
{
	char *endptr;
	int ret = 0, val;

	if (!*++argv) {
		const char *gconfig;

		/* Get the current G mode */
		if ((ret = wl_get(wl, cmd->get, &val, sizeof(val))))
			return -1;

		switch (val) {
		case GMODE_LEGACY_B:
			gconfig = "54g Legacy B";
			break;
		case GMODE_AUTO:
			gconfig = "54g Auto";
			break;
		case GMODE_ONLY:
			gconfig = "54g Only";
			break;
		case GMODE_PERFORMANCE:
			gconfig = "54g Performance";
			break;
		case GMODE_LRS:
			gconfig = "54g LRS";
			break;
		default:
			gconfig = "unknown";
			break;
		}

		printf("%s (%d)\n", gconfig, val);

	} else {
		/* Set the new G mode */

		if (!strnicmp(*argv, "legacy", 6))
			val = GMODE_LEGACY_B;
		else if (!strnicmp(*argv, "auto", 4))
			val = GMODE_AUTO;
		else if (!strnicmp(*argv, "gonly", 5))
			val = GMODE_ONLY;
		else if (!strnicmp(*argv, "perf", 4))
			val = GMODE_PERFORMANCE;
		else if (!strnicmp(*argv, "lrs", 3))
			val = GMODE_LRS;
		else {
			val = strtol(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}
		}

		/* Set the gmode configration */
		if ((ret = wl_set(wl, cmd->set, &val, sizeof(val))))
			goto done;

	}

done:
	return (ret);
}


static int
wl_reg(void *wl, cmd_t *cmd, char **argv)
{
	int reg;
	int ret;
	struct {
		int val;
		int band;
	} x;
	char *endptr;
	uint argc;

	/* eat command name */
	argv++;

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* required arg: reg offset */
	if (argc < 1)
		return -1;

	reg = strtol(argv[0], &endptr, 0);
	if (*endptr != '\0')
		return -1;

	x.band = WLC_BAND_AUTO;

	/* Second arg: value or band */
	if (argc >= 2) {
		if (!stricmp(argv[1], "a"))
			x.band = WLC_BAND_5G;
		else if (!stricmp(argv[1], "b"))
			x.band = WLC_BAND_2G;
		else {
			x.val = strtol(argv[1], &endptr, 0);
			if (*endptr != '\0')
				return (-1);
		}
	}

	/* Third arg: band */
	if (argc >= 3) {
		if (!stricmp(argv[2], "a"))
			x.band = WLC_BAND_5G;
		else if (!stricmp(argv[2], "b"))
			x.band = WLC_BAND_2G;
		else
			return (-1);
	}

	x.val = (x.val << 16) | (reg & 0xffff);

	/* issue the get or set ioctl */
	if ((argc == 1) || ((argc == 2) && (x.band != WLC_BAND_AUTO))) {
		if ((ret = wl_get(wl, cmd->get, &x, sizeof(x))) < 0)
			return (ret);
		printf("0x%04x\n", (uint16)x.val);
	}
	else
		ret = wl_set(wl, cmd->set, &x, sizeof(x));

	return (ret);
}

static int
wl_gpioout(void *wl, cmd_t *cmd, char **argv)
{
	uint32 mask;
	uint32 val;
	char *endptr;
	uint argc;
	uint32 *int_ptr;

	val = 0;

	/* eat command name */
	argv++;

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* Get and print the values */
	if (argc == 0) {
		uint32 gpio_cntrl;
		uint32 gpio_out;
		uint32 gpio_outen;

		if (wl_iovar_get(wl, "gpioout", buf, sizeof(uint32) *3))
			return -1;
		gpio_cntrl = ((uint32 *)buf)[0];
		gpio_out = ((uint32 *)buf)[1];
		gpio_outen = ((uint32 *)buf)[2];

		printf("gpiocontrol 0x%x gpioout 0x%x gpioouten 0x%x\n", gpio_cntrl,
		       gpio_out, gpio_outen);

		return 0;
	}

	/* required arg: mask value */
	if (argc < 2)
		return -1;

	mask = strtoul(argv[0], &endptr, 0);
	if (*endptr != '\0')
		return -1;

	val = strtoul(argv[1], &endptr, 0);
	if (*endptr != '\0')
		return -1;

	if ((~mask & val) != 0)
		return -1;

	int_ptr = (uint32 *)buf;
	memcpy(int_ptr, (const void *)&mask, sizeof(mask));
	int_ptr++;
	memcpy(int_ptr, (const void *)&val, sizeof(val));

	return wl_iovar_set(wl, "gpioout", buf, sizeof(uint32) *2);
}

static int
wl_macreg(void *wl, cmd_t *cmd, char **argv)
{
	int reg;
	int size;
	uint32 val;
	int ret;
	char *endptr;
	rw_reg_t rwt;
	uint argc;

	val = 0;

	/* eat command name */
	argv++;

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	/* required arg: reg offset */
	if (argc < 1)
		return -1;

	reg = strtol(argv[0], &endptr, 0);
	if (*endptr != '\0')
		return -1;

	/* required arg: reg size */
	if (argc < 2)
		return (-1);

	size = strtol(argv[1], &endptr, 0);
	if (*endptr != '\0')
		return -1;

	rwt.band = WLC_BAND_AUTO;

	/* Third arg: new value or band */
	if (argc >= 3) {
		if (!stricmp(argv[2], "a"))
			rwt.band = WLC_BAND_5G;
		else if (!stricmp(argv[2], "b"))
			rwt.band = WLC_BAND_2G;
		else {
			val = strtoul(argv[2], &endptr, 0);
			if (*endptr != '\0')
				return -1;
		}

	}

	/* Fourth arg: band */
	if (argc >= 4) {
		if (!stricmp(argv[3], "a"))
			rwt.band = WLC_BAND_5G;
		else if (!stricmp(argv[3], "b"))
			rwt.band = WLC_BAND_2G;
		else
			return (-1);
	}

	if ((argc == 2) || ((argc == 3) && (rwt.band != WLC_BAND_AUTO))) {
		rwt.byteoff = reg;
		rwt.size = size;
		if ((ret = wl_get(wl, cmd->get, &rwt, sizeof(rw_reg_t))) < 0)
			return (ret);
		printf("0x%04x\n", rwt.val);
	}
	else {
		rwt.byteoff = reg;
		rwt.size = size;
		rwt.val = val;
		ret = wl_set(wl, cmd->set, &rwt, sizeof(rw_reg_t));
	}

	return (ret);
}

/*
 * get or get a band specific variable
 * the band can be a/b/all or omitted. "all"(set only)
 * means all supported bands. blank means current band
 */
static int
wl_band_elm(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	struct {
		int val;
		int band;
	} x;
	char *endptr;
	uint argc;

	/* eat command name */
	argv++;

	/* arg count */
	for (argc = 0; argv[argc]; argc++)
		;

	x.val = 0;
	x.band = WLC_BAND_AUTO;

	/* First arg: value or band */
	if (argc >= 1) {
		if (!stricmp(argv[0], "a"))
			x.band = WLC_BAND_5G;
		else if (!stricmp(argv[0], "b"))
			x.band = WLC_BAND_2G;
		else if (!stricmp(argv[0], "all"))
			x.band = WLC_BAND_ALL;
		else {
			x.val = strtol(argv[0], &endptr, 0);
			if (*endptr != '\0')
				return (-1);
		}
	}

	/* Second arg: band */
	if (argc >= 2) {
		if (!stricmp(argv[1], "a"))
			x.band = WLC_BAND_5G;
		else if (!stricmp(argv[1], "b"))
			x.band = WLC_BAND_2G;
		else if (!stricmp(argv[1], "all"))
			x.band = WLC_BAND_ALL;
		else
			return (-1);
	}

	/* issue the get or set ioctl */
	if ((argc == 0) || ((argc == 1) && (x.band != WLC_BAND_AUTO))) {
		if (x.band == WLC_BAND_ALL) {
			printf("band option \"all\" is for set only, not get\n");
			return (-1);
		}

		if ((ret = wl_get(wl, cmd->get, &x, sizeof(x))) < 0)
			return (ret);

		printf("%s is 0x%04x(%d)\n", cmd->name, (uint16)x.val, x.val);
	}
	else
		ret = wl_set(wl, cmd->set, &x, sizeof(x));

	return (ret);
}

/* Command may or may not take a MAC address */
static int
wl_rssi(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	scb_val_t scb_val;

	if (!*++argv) {
		if ((ret = wl_get(wl, cmd->get, &scb_val.val, sizeof(scb_val))) < 0)
			return ret;
		printf("%d\n", scb_val.val);
		return 0;
	} else {
		if (!wl_ether_atoe(*argv, &scb_val.ea))
			return -1;
		if ((ret = wl_get(wl, cmd->get, &scb_val.val, sizeof(scb_val))) < 0)
			return ret;
		printf("%d\n", scb_val.val);
		return 0;
	}
}

static int
wl_phy_rssi_ant(void *wl, cmd_t *cmd, char **argv)
{
	int ret = 0;
	uint i;
	wl_rssi_ant_t *rssi_ant_p;

	if (!*++argv) {
		/* Get */
		void *ptr = NULL;

		if ((ret = wl_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;

		rssi_ant_p = (wl_rssi_ant_t *)ptr;

		if (rssi_ant_p->count == 0) {
			printf("not supported on this chip\n");
		} else {
			for (i = 0; i < rssi_ant_p->count; i++)
				printf("rssi[%d] %d  ", i, rssi_ant_p->rssi_ant[i]);
			printf("\n");
		}
	} else {
		ret = USAGE_ERROR;
	}
	return ret;
}

/* Commands that take a MAC address */
static int
wl_mac(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	struct ether_addr ea;

	if (!*++argv) {
		if ((ret = wl_get(wl, cmd->get, &ea, ETHER_ADDR_LEN)) < 0)
			return ret;
		printf("%s\n", wl_ether_etoa(&ea));
		return 0;
	} else {
		if (!wl_ether_atoe(*argv, &ea))
			return -1;
		return wl_set(wl, cmd->set, &ea, ETHER_ADDR_LEN);
	}
}

static int
wlu_dump(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	char *dump_buf;
	int bcmerr;

	if (cmd->get < 0)
		return -1;

	dump_buf = malloc(WL_DUMP_BUF_LEN);
	if (dump_buf == NULL) {
		fprintf(stderr, "Failed to allocate dump buffer of %d bytes\n", WL_DUMP_BUF_LEN);
		return -1;
	}
	memset(dump_buf, 0, WL_DUMP_BUF_LEN);

	/* skip the command name */
	argv++;

	/* If no args given, get the subset of 'wl dump all'
	 * Otherwise, if args are given, they are the dump section names.
	 */
	if (*argv == NULL) {
		/* query for the 'dump' without any argument */
		ret = wl_iovar_getbuf(wl, "dump", NULL, 0, dump_buf, WL_DUMP_BUF_LEN);

		/* if the query is successful, continue on and print the result. */

		/* if the query fails, check for a legacy driver that does not support
		 * the "dump" iovar, and instead issue a WLC_DUMP ioctl.
		 */
		if (ret) {
			wl_iovar_getint(wl, "bcmerror", &bcmerr);
			if (bcmerr == BCME_UNSUPPORTED) {
				ret = wl_get(wl, WLC_DUMP, dump_buf, WL_DUMP_BUF_LEN);
				if (ret) {
					fprintf(stderr, "dump: error on query of WLC_DUMP\n");
					ret = IOCTL_ERROR;
				}
			} else {
				fprintf(stderr, "dump: error on query of dump list\n");
				ret = IOCTL_ERROR;
			}
		}
	} else {
		/* create the dump section name list */
		while (*argv) {
			/* add space delimiter if this is not the first section name */
			if (dump_buf[0] != '\0')
				strcat(dump_buf, " ");

			strcat(dump_buf, *argv);

			argv++;
		}

		/* This is a "space" added at end of last argument */
		strcat(dump_buf, " ");

		ret = wl_iovar_getbuf(wl, "dump", dump_buf, strlen(dump_buf),
		                      dump_buf, WL_DUMP_BUF_LEN);
	}

	if (!ret) {
		fputs(dump_buf, stdout);
	}

	free(dump_buf);

	return ret;
}


static int
wlu_srdump(void *wl, cmd_t *cmd, char **argv)
{
	int ret, i, nw;
	uint16 *words = (uint16 *)&buf[8];

	srom_rw_t   *srt;

	nw = 64;
	srt = (srom_rw_t *)buf;
	srt->byteoff = 0;
	srt->nbytes = 2 * nw;

	if (cmd->get < 0)
		return -1;
	if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
		return ret;
	if (words[32 /* SROM4_SIGN */] == 0x5372 /* SROM4_SIGNATURE */) {
		nw = 220 /* SROM4_WORDS */;
		srt->nbytes = nw * 2;
		if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
			return ret;
	}
	for (i = 0; i < nw; i++) {
		if ((i % 8) == 0)
			printf("\n  srom[%03d]:  ", i);
		printf("0x%04x  ", words[i]);
	}
	printf("\n");

	return 0;
}

static int
wlu_srwrite(void *wl, cmd_t *cmd, char **argv)
{
#if	defined(_CFE_)
	return CFE_ERR_UNSUPPORTED;
#else
	char *arg, *p;
	FILE *fp = NULL;
	int ret = 0, erase;
	uint i, len;
	srom_rw_t *srt = (srom_rw_t *)buf;

	erase = !strcmp(*argv, "srclear");

	/* We need at least one arg */
	if (!*++argv)
		return -1;

	arg = *argv++;

	if (erase) {
		if (*argv) {
			printf("srclear takes only one arg\n");
			ret = -3;
			goto out;
		}
		len = strtoul(arg, &p, 0);
		srt->byteoff = 0x55aa;
	} else if (!*argv) {
		/* Only one arg, it better be a file name */
		if (!(fp = fopen(arg, "rb"))) {
			fprintf(stderr, "%s: No such file or directory\n", arg);
			return -2;
		}

		len = fread(srt->buf, 1, 441, fp);
		if ((ret = ferror(fp))) {
			printf("\nerror %d reading %s\n", ret, arg);
			ret = -3;
			goto out;
		}

		if (!feof(fp)) {
			printf("\nFile %s is too large\n", arg);
			ret = -4;
			goto out;
		}

		if (len == 440) {
			if (srt->buf[32 /* SROM4_SIGN */] != 0x5372 /* SROM4_SIGNATURE */) {
				printf("\nFile %s is 440 bytes but lacks a REV4 signature\n", arg);
				ret = -5;
				goto out;
			}
		} else if (len != 128) {
			printf("\nFile %s is %d bytes, not 128 or 440 bytes\n", arg, len);
			ret = -6;
			goto out;
		}

		srt->byteoff = 0;
	} else {
		/* More than 1 arg, first is offset, rest are data. */
		srt->byteoff = strtoul(arg, &p, 0);
		if (*p != '\0')
			goto nout;

		i = 0;
		while ((arg = *argv++) != NULL) {
			srt->buf[i++] = (uint16)strtoul(arg, &p, 0);
			if (*p != '\0') {
nout:
				printf("\n%s is not an integer\n", arg);
				ret = -7;
				goto out;
			}
		}

		if (srt->byteoff & 1) {
			printf("Byte offset (%d) is odd or negative\n", srt->byteoff);
			ret = -8;
			goto out;
		}

		len = 2 * i;
		if ((srt->byteoff + len) > 440) {
			printf("Data extends past 440 bytes\n");
			ret = -9;
			goto out;
		}
	}
	srt->nbytes = len;

	fprintf(stderr, "Writing srom. ioctl %d, iolen %d, sroff %d, len %d\n",
	        cmd->set, len + 8, srt->byteoff, srt->nbytes);

	if ((ret = wl_set(wl, cmd->set, buf, len + 8)) < 0) {
		printf("\nError %d writing the srom\n", ret);
	}

out:
	fflush(stdout);
	if (fp)
		fclose(fp);
	return ret;
#endif /* _CFE_ */
}

static dbg_msg_t wl_msgs[] = {
	{WL_ERROR_VAL, 	"error"},
	{WL_ERROR_VAL, 	"err"},
	{WL_TRACE_VAL, 	"trace"},
	{WL_PRHDRS_VAL,	"prhdrs"},
	{WL_PRPKT_VAL,	"prpkt"},
	{WL_INFORM_VAL,	"inform"},
	{WL_INFORM_VAL,	"info"},
	{WL_INFORM_VAL,	"inf"},
	{WL_TMP_VAL,	"tmp"},
	{WL_OID_VAL,	"oid"},
	{WL_RATE_VAL,	"rate"},
	{WL_ASSOC_VAL,	"assoc"},
	{WL_ASSOC_VAL,	"as"},
	{WL_PRUSR_VAL,	"prusr"},
	{WL_PS_VAL,	"ps"},
	{WL_TXPWR_VAL,	"txpwr"},
	{WL_TXPWR_VAL,	"pwr"},
	{WL_GMODE_VAL,	"gmode"},
	{WL_DUAL_VAL,	"dual"},
	{WL_WSEC_VAL,	"wsec"},
	{WL_WSEC_DUMP_VAL,	"wsec_dump"},
	{WL_LOG_VAL,	"log"},
	{WL_NRSSI_VAL,	"nrssi"},
	{WL_LOFT_VAL,	"loft"},
	{WL_REGULATORY_VAL,	"regulatory"},
	{WL_ACI_VAL,	"aci"},
	{WL_RADAR_VAL,	"radar"},
	{WL_MPC_VAL,	"mpc"},
	{WL_APSTA_VAL,	"apsta"},
	{WL_DFS_VAL,	"dfs"},
	{WL_BA_VAL,	"ba"},
	{WL_NITRO_VAL,	"nitro"},
	{WL_CAC_VAL,	"cac"},
	{WL_AMSDU_VAL,	"amsdu"},
	{WL_AMPDU_VAL,	"ampdu"},
	{0,		NULL}
};

static int
wl_msglevel(void *wl, cmd_t *cmd, char **argv)
{
	int ret, i;
	uint val, last_val = 0, msglevel, msglevel_add = 0, msglevel_del = 0;
	char *endptr;
	dbg_msg_t *dbg_msg = wl_msgs;

	if ((ret = wl_get(wl, cmd->get, &msglevel, sizeof(int))) < 0)
		return (ret);

	if (!*++argv) {
		printf("0x%x ", msglevel);
		for (i = 0; (val = dbg_msg[i].value); i++) {
			if ((msglevel & val) && (val != last_val))
				printf(" %s", dbg_msg[i].string);
			last_val = val;
		}
		printf("\n");
		return (0);
	}

	while (*argv) {
		char *s = *argv;
		if (*s == '+' || *s == '-')
			s++;
		else
			msglevel_del = ~0;	/* make the whole list absolute */
		val = strtoul(s, &endptr, 0);
		/* not a plain integer if not all the string was parsed by strtoul */
		if (*endptr != '\0') {
			for (i = 0; (val = dbg_msg[i].value); i++)
				if (stricmp(dbg_msg[i].string, s) == 0)
					break;
			if (!val)
				goto usage;
		}
		if (**argv == '-')
			msglevel_del |= val;
		else
			msglevel_add |= val;
		++argv;
	}

	msglevel &= ~msglevel_del;
	msglevel |= msglevel_add;

	return (wl_set(wl, cmd->set, &msglevel, sizeof(int)));

usage:
	fprintf(stderr, "msg values may be a list of numbers or names from the following set.\n");
	fprintf(stderr, "Use a + or - prefix to make an incremental change.");

	for (i = 0; (val = dbg_msg[i].value); i++) {
		if (val != last_val)
			fprintf(stderr, "\n0x%04x %s", val, dbg_msg[i].string);
		else
			fprintf(stderr, ", %s", dbg_msg[i].string);
		last_val = val;
	}
	fprintf(stderr, "\n");

	return 0;
}

/* take rate arg in units of 500Kbits/s and print it in units of Mbit/s */
static void
wl_printrate(int val)
{
	char rate_buf[32];

	printf("%s\n", rate_int2string(rate_buf, val));
}

/* convert rate string in Mbit/s format, like "11", "5.5", to internal 500 Kbit/s units */
static int
rate_string2int(char *s)
{
	if (!stricmp(s, "-1"))
		return (0);
	if (!stricmp(s, "5.5"))
		return (11);
	return (atoi(s) * 2);
}

/* convert rate internal 500 Kbits/s units to string in Mbits/s format, like "11", "5.5" */
static char*
rate_int2string(char *rate_buf, int val)
{
	if ((val == -1) || (val == 0))
		sprintf(rate_buf, "auto");
	else if (val > 1000) /* this indicates that units are kbps */
		sprintf(rate_buf, "%d Kbps", val);
	else
		sprintf(rate_buf, "%d%s Mbps", (val / 2), (val & 1) ? ".5" : "");
	return (rate_buf);
}

/* handles both "rate" and "mrate", which makes the flow a bit complex */
static int
wl_rate_mrate(void *wl, cmd_t *cmd, char **argv)
{
	int error;
	int val;
	int band;
	int list[3];
	char aname[sizeof("a_mrate") + 1];
	char bgname[sizeof("bg_mrate") + 1];
	char *name;

	sprintf(aname, "a_%s", *argv);
	sprintf(bgname, "bg_%s", *argv);


	if ((error = wl_get(wl, WLC_GET_BAND, &band, sizeof(uint))) < 0)
		return error;

	if ((error = wl_get(wl, WLC_GET_BANDLIST, list, sizeof(list))) < 0)
		return error;

	if (!list[0])
		return -1;
	else if (list[0] > 2)
		list[0] = 2;

	if ((!strcmp(*argv, "rate"))) {
		/* it is "rate" */
		if (!*++argv) {
			/* it is "rate" get. handle it here */
			/* WLC_GET_RATE processing */
			if ((error = wl_get(wl, cmd->get, &val, sizeof(int))) < 0)
				return error;

			wl_printrate(val);
			return 0;
		}
		else
			--argv; /* move it back for later processing */
	}

	switch (band) {
	case WLC_BAND_AUTO :
		if (list[0] > 1)
			return -1;
		else if (list[1] == WLC_BAND_5G)
			name = (char *)aname;
		else if (list[1] == WLC_BAND_2G)
			name = (char *)bgname;
		else
			return -1;

		break;

	case WLC_BAND_5G :
		name = (char *)aname;
		break;

	case WLC_BAND_2G :
		name = (char *)bgname;
		break;

	default :
		return -1;
		break;
	}

	if (!*++argv) {
		/* it is "mrate" get */
		if ((error = wl_iovar_getint(wl, name, &val) < 0))
			return error;

		if (val == 0)
			printf("auto\n");
		else
			wl_printrate(val);

		return 0;
	} else {
		val = rate_string2int(*argv);
		return wl_iovar_setint(wl, name, val);
	}
}

static int
wl_wepstatus(void *wl, cmd_t *cmd, char **argv)
{
	int val, error;
	const char *name = "wsec";
	int wsec;

	if (!*++argv) {
		if ((error = wl_iovar_getint(wl, name, &val) < 0))
			return error;

		printf("%d\n", val);
		return 0;
	} else {
		val = atoi(*argv);
		if ((error = wl_iovar_getint(wl, name, &wsec) < 0))
			return error;

		if (val)
			wsec |= WEP_ENABLED;
		else
			wsec &= ~WEP_ENABLED;

		return wl_iovar_setint(wl, name, wsec);
	}
}

static int
wl_phy_rate(void *wl, cmd_t *cmd, char **argv)
{
	int val, error;
	int *pval;
	char *p;

	if (!*++argv) {
		pval = (int *) buf;
		strcpy(buf, cmd->name);
		if ((error = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
			return (error);
		val = *pval;
		wl_printrate(val);
		return (0);
	} else {
		val = rate_string2int(*argv);

		/* construct an iovar */
		strcpy(buf, cmd->name);
		p = &buf[strlen(buf) + 1];
		memcpy(p, &val, sizeof(uint));
		p += sizeof(uint);

		return (wl_set(wl, cmd->set, &buf, (p - buf)));
	}
}

static int
wl_nrate(void *wl, cmd_t *cmd, char **argv)
{
	miniopt_t to;
	const char* fn_name = "wl_nrate", *rspec_auto = "auto";
	bool mcs_set = FALSE, legacy_set = FALSE, stf_set = FALSE;
	int err, opt_err;
	uint32 val;
	uint32 nrate = 0;
	uint stf;

	/* toss the command name */
	argv++;

	if (!*argv) {
		if (cmd->get < 0)
			return -1;
		if ((err = wl_iovar_getint(wl, "nrate", (int*)&val)) < 0)
			return err;

		if (!val) {
			printf("auto\n");
		} else {
			stf = (uint)((val & NRATE_STF_MASK) >> NRATE_STF_SHIFT);
			nrate = (val & NRATE_RATE_MASK);
			if (val & NRATE_OVERRIDE)
				rspec_auto = "fixed";

			if (val & NRATE_MCS_INUSE)
				printf("mcs index %d stf mode %d %s\n",
				       nrate, stf, rspec_auto);
			else
				printf("legacy rate %d%s Mbps stf mode %d %s\n",
				       nrate/2, (nrate % 2)?".5":"", stf, rspec_auto);
		}
		return 0;
	}

	miniopt_init(&to, fn_name, NULL);
	while ((opt_err = miniopt(&to, argv)) != -1) {
		if (opt_err == 1) {
			err = -1;
			goto exit;
		}
		argv += to.consumed;

		if (to.opt == 'r') {
			if (!to.good_int) {
				/* special case check for "-r 5.5" */
				if (!strcmp(to.valstr, "5.5")) {
					to.val = 11;
				} else {
					fprintf(stderr,
						"%s: could not parse \"%s\" as a rate value\n",
						fn_name, to.valstr);
					err = -1;
					goto exit;
				}
			} else
			      to.val = to.val*2;
			if (mcs_set) {
				fprintf(stderr, "%s: cannot use -r and -m\n", fn_name);
				err = -1;
				goto exit;
			}
			nrate |= to.val & NRATE_RATE_MASK;
			legacy_set = TRUE;
		}
		if (to.opt == 'm') {
			if (!to.good_int) {
				fprintf(stderr,
					"%s: could not parse \"%s\" as an int for mcs\n",
					fn_name, to.valstr);
				err = -1;
				goto exit;
			}
			if (legacy_set) {
				fprintf(stderr, "%s: cannot use -r and -m\n", fn_name);
				err = -1;
				goto exit;
			}
			mcs_set = TRUE;
			nrate |= to.val & NRATE_RATE_MASK;
			nrate |= NRATE_MCS_INUSE;
		}
		if (to.opt == 's') {
			if (!to.good_int) {
				fprintf(stderr,
					"%s: could not parse \"%s\" as an int for stf mode\n",
					fn_name, to.valstr);
				err = -1;
				goto exit;
			}
			nrate |= (to.val << NRATE_STF_SHIFT) & NRATE_STF_MASK;
			stf_set = TRUE;
		}
	}
	if (!stf_set) {
		stf = 0;
		if (legacy_set)
			stf = NRATE_STF_SISO;	/* SISO */
		else if (mcs_set) {
			if ((nrate & NRATE_RATE_MASK) <= HIGHEST_SINGLE_STREAM_MCS ||
			    (nrate & NRATE_RATE_MASK) == 32)
				stf = NRATE_STF_SISO;	/* SISO */
			else
				stf = NRATE_STF_SDM;	/* SDM */
		}
		nrate |= (stf << NRATE_STF_SHIFT) & NRATE_STF_MASK;
	}

	if (legacy_set || mcs_set) {
		err = wl_iovar_setint(wl, "nrate", (int)nrate);
	} else {
		fprintf(stderr, "%s: you need to set a legacy or mcs rate\n", fn_name);
		err = -1;
	}

exit:
	return err;
}

static int
wl_assoc_info(void *wl, cmd_t *cmd, char **argv)
{
	uint i, req_ies_len = 0, resp_ies_len = 0;
	wl_assoc_info_t assoc_info;
	int ret;
	uint8 *pbuf;

	/* get the generic association information */
	strcpy(buf, cmd->name);
	if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
		return ret;

	memcpy(&assoc_info, buf, sizeof(wl_assoc_info_t));

	printf("Assoc req:\n");
	printf("\tlen 0x%x\n", assoc_info.req_len);
	if (assoc_info.req_len) {
		printf("\tcapab  0x%x\n", ltoh16(assoc_info.req.capability));
		printf("\tlisten 0x%x\n", ltoh16(assoc_info.req.listen));
		req_ies_len = assoc_info.req_len - sizeof(struct dot11_assoc_req);
		if (assoc_info.flags & WLC_ASSOC_REQ_IS_REASSOC) {
			printf("\treassoc bssid %s\n",
				wl_ether_etoa(&assoc_info.reassoc_bssid));
			req_ies_len -= ETHER_ADDR_LEN;
		}
	}

	/* get the association req IE's if there are any */
	if (req_ies_len) {
		strcpy(buf, "assoc_req_ies");
		if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
			return ret;

		printf("assoc req IEs:\n\t");
		for (i = 1, pbuf = (uint8*)buf; i <= req_ies_len; i++) {
			printf("0x%02x ", *pbuf++);
			if (!(i%8))
				printf("\n\t");
		}
	}

	printf("\nAssoc resp:\n");
	printf("\tlen 0x%x\n", assoc_info.resp_len);
	if (assoc_info.resp_len) {
		printf("\tcapab  0x%x\n", ltoh16(assoc_info.resp.capability));
		printf("\tstatus 0x%x\n", ltoh16(assoc_info.resp.status));
		printf("\taid    0x%x\n", ltoh16(assoc_info.resp.aid));
		resp_ies_len = assoc_info.resp_len - sizeof(struct dot11_assoc_resp);
	}

	/* get the association resp IE's if there are any */
	if (resp_ies_len) {
		strcpy(buf, "assoc_resp_ies");
		if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
			return ret;

		printf("assoc resp IEs:\n\t");
		for (i = 1, pbuf = (uint8*)buf; i <= resp_ies_len; i++) {
			printf(" 0x%02x ", *pbuf++);
			if (!(i%8))
				printf("\n\t");

		}
	}
	printf("\n");

	return 0;
}

#ifdef BCMWPA2
static int
wl_pmkid_info(void *wl, cmd_t *cmd, char**argv)
{
	int i, j, ret;
	int *pval;
	pmkid_list_t *pmkid_info;

	if (!*++argv) {
		pval = (int *) buf;
		strcpy(buf, cmd->name);
		if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
			return ret;

		pmkid_info = (pmkid_list_t *)buf;
		printf("\npmkid entries : %d\n", pmkid_info->npmkid);

		for (i = 0; i < (int)pmkid_info->npmkid; i++) {
			printf("\tPMKID[%d]: %s =",
				i, wl_ether_etoa(&pmkid_info->pmkid[i].BSSID));
			for (j = 0; j < WPA2_PMKID_LEN; j++)
				printf("%02x ", pmkid_info->pmkid[i].PMKID[j]);
			printf("\n");
		}
	}
	else {
#ifdef test_pmkid_info
		char eaddr[6] = {0x0, 0x0, 0x1, 0x2, 0x3, 0x5};
		char eaddr1[6] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
		char id[WPA2_PMKID_LEN], id1[WPA2_PMKID_LEN];
		int i, len = (sizeof(uint32) + 2*(sizeof(pmkid_t)));

		/* check that the set uses to "test" cmd */
		if (strcmp(*argv, "test")) {
			printf("\t wl pmkid_info only supports `test` a test specific set\n");
			return -1;
		}
		if ((pmkid_info = (pmkid_list_t *)malloc(len)) == NULL)	{
			printf("\tfailed to allocate buffer\n");
			return -1;
		}

		printf("\toverwriting pmkid table with test pattern\n");
		for (i = 0; i < (int)sizeof(id); i++) {
			id[i] = i;
			id1[i] = (i*2);
		}

		/* "test" - creates two PMKID entries and sets the table to that */
		pmkid_info->npmkid = 2;
		memcpy(&pmkid_info->pmkid[0].BSSID.octet[0], &eaddr[0], ETHER_ADDR_LEN);
		memcpy(&pmkid_info->pmkid[0].PMKID[0], &id[0], WPA2_PMKID_LEN);
		memcpy(&pmkid_info->pmkid[1].BSSID.octet[0], &eaddr1[0], ETHER_ADDR_LEN);
		memcpy(&pmkid_info->pmkid[1].PMKID[0], &id1[0], WPA2_PMKID_LEN);

		ret = wl_var_setbuf(wl, cmd->name, pmkid_info, len);

		free(pmkid_info);

		return ret;
#else
		printf("\tset cmd ignored\n");
#endif /* test_pmkid_info */
	}

	return 0;
}
#endif /* BCMWPA2 */

static int
wl_rateset(void *wl, cmd_t *cmd, char **argv)
{
	wl_rateset_t rs, defrs;
	int error;
	uint i;

	error = 0;

	argv++;

	if (*argv == NULL) {
		/* get current rateset */
		if ((error = wl_get(wl, WLC_GET_CURR_RATESET, &rs, sizeof(wl_rateset_t))) < 0)
			return (error);

		dump_rateset(rs.rates, rs.count);
		printf("\n");
	} else {
		/* get default rateset */
		if ((error = wl_get(wl, WLC_GET_RATESET, &defrs, sizeof(wl_rateset_t))) < 0)
			return (error);

		if (!stricmp(*argv, "all")) {
			for (i = 0; i < defrs.count; i++)
				defrs.rates[i] |= 0x80;
			error = wl_set(wl, WLC_SET_RATESET, &defrs, sizeof(wl_rateset_t));
		}
		else if (!stricmp(*argv, "default")) {
			error = wl_set(wl, WLC_SET_RATESET, &defrs, sizeof(wl_rateset_t));
		}
		else {	/* arbitrary list */
			wl_parse_rateset(&defrs, argv);
			/* check for common error of no basic rates */
			for (i = 0; i < defrs.count; i++) {
				if (defrs.rates[i] & 0x80)
					break;
			}
			if (i < defrs.count) {
				error = wl_set(wl, WLC_SET_RATESET, &defrs, sizeof(wl_rateset_t));
			} else {
				error = -1;
				fprintf(stderr,
				"Bad Args: at least one rate must be marked Basic\n");
			}

		}

	}
	return (error);
}

static int
wl_sup_rateset(void *wl, cmd_t *cmd, char **argv)
{
	wl_rateset_t rs;
	bool got_basic;
	int error;
	uint i;

	error = 0;
	memset((char*)&rs, 0, sizeof(wl_rateset_t));

	argv++;

	if (*argv == NULL) {
		/* get rateset */
		if ((error = wl_get(wl, cmd->get, &rs, sizeof(wl_rateset_t))) < 0)
			return (error);

		dump_rateset(rs.rates, rs.count);
		printf("\n");
	} else {
		if (!stricmp(*argv, "-1") || !stricmp(*argv, "0")) {
			/* set an empty rateset */
			error = wl_set(wl, cmd->set, &rs, sizeof(wl_rateset_t));
		}
		else {	/* set the specified rateset */
			wl_parse_rateset(&rs, argv);
			/* check for common error of including a basic rate */
			got_basic = FALSE;
			for (i = 0; i < rs.count; i++) {
				if (rs.rates[i] & 0x80) {
					rs.rates[i] &= 0x7F;
					got_basic = TRUE;
				}
			}
			if (got_basic) {
				fprintf(stderr,
				"Warning: Basic rate attribute ignored for \"%s\" command\n",
				cmd->name);
			}
			error = wl_set(wl, cmd->set, &rs, sizeof(wl_rateset_t));
		}

	}
	return (error);
}

static int
wl_parse_rateset(wl_rateset_t* rs, char **argv)
{
	char* endp;
	char* arg;
	int r;
	int error = 0;

	memset(rs, 0, sizeof(*rs));

	while ((arg = *argv++) != NULL) {
		if (rs->count >= WL_NUMRATES) {
			fprintf(stderr,
			"parsing \"%s\", too many rates specified, max is %d rates\n",
			arg, WL_NUMRATES);
			error = -1;
			break;
		}

		/* convert the rate number to a 500kbps rate by multiplying by 2 */
		r = (int)(strtoul(arg, &endp, 0) * 2);
		if (endp == arg) {
			fprintf(stderr, "unable to convert the rate parameter \"%s\"\n", arg);
			error = -1;
			break;
		}

		/* parse a .5 specially */
		if (!strncmp(endp, ".5", 2)) {
			r += 1;
			endp += 2;
		}

		/* strip trailing space */
		while (isspace((int)endp[0]))
			endp++;

		/* check for a basic rate specifier */
		if (!stricmp(endp, "b") || !stricmp(endp, "(b)")) {
			r |= 0x80;
		} else if (endp[0] != '\0') {
			fprintf(stderr,
				"unable to convert trailing characters"
				" \"%s\" in the rate parameter \"%s\"\n",
				endp, arg);
			error = -1;
			break;
		}
		rs->rates[rs->count++] = r;
	}

	return error;
}

static int
wl_channel(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	channel_info_t ci;

	if (!*++argv) {
		memset(&ci, 0, sizeof(ci));
		if ((ret = wl_get(wl, cmd->get, &ci, sizeof(channel_info_t))) < 0)
			return ret;
		if (ci.scan_channel) {
			printf("Scan in progress.\n");
			printf("current scan channel\t%d\n", ci.scan_channel);
		} else {
			printf("No scan in progress.\n");
		}
		printf("current mac channel\t%d\n", ci.hw_channel);
		printf("target channel\t%d\n", ci.target_channel);
		return 0;
	} else {
		ci.target_channel = atoi(*argv);
		ret =  wl_set(wl, cmd->set, &ci.target_channel, sizeof(int));
		return ret;
	}
}

static int
wl_chanspec(void *wl, cmd_t *cmd, char **argv)
{
	miniopt_t to;
	const char* fn_name = "wl_chanspec";
	bool band_set = FALSE, ch_set = FALSE, bw_set = FALSE, ctl_sb_set = FALSE;
	int err, opt_err;
	uint32 val;
	chanspec_t chanspec = 0;

	/* toss the command name */
	argv++;

	if (!*argv) {
		if (cmd->get < 0)
			return -1;
		if ((err = wl_iovar_getint(wl, cmd->name, (int*)&val)) < 0)
			return err;

		wf_chspec_ntoa((chanspec_t)val, buf);
		printf("%s (0x%x)\n", buf, val);
		return 0;
	}


	if ((chanspec = wf_chspec_aton(*argv))) {
		err = wl_iovar_setint(wl, cmd->name, (int)chanspec);
	} else {
		miniopt_init(&to, fn_name, NULL);
		while ((opt_err = miniopt(&to, argv)) != -1) {
			if (opt_err == 1) {
				err = -1;
				goto exit;
			}
			argv += to.consumed;

			if (to.opt == 'c') {
				if (!to.good_int) {
					fprintf(stderr,
						"%s: could not parse \"%s\" as an int for"
						" the channel\n", fn_name, to.valstr);
					err = -1;
					goto exit;
				}
				if (to.val > 224) {
					fprintf(stderr, "%s: invalid channel %d\n",
						fn_name, to.val);
					err = -1;
					goto exit;
				}
				chanspec |= to.val;
				ch_set = TRUE;
			}
			if (to.opt == 'b') {
				if (!to.good_int) {
					fprintf(stderr,
						"%s: could not parse \"%s\" as an int for band\n",
						fn_name, to.valstr);
					err = -1;
					goto exit;
				}
				if ((to.val != 5) && (to.val != 2)) {
					fprintf(stderr,
						"%s: invalid band %d\n",
						fn_name, to.val);
					err = -1;
					goto exit;
				}
				if (to.val == 5)
					chanspec |= WL_CHANSPEC_BAND_5G;
				else
					chanspec |= WL_CHANSPEC_BAND_2G;
				band_set = TRUE;
			}
			if (to.opt == 'w') {
				if (!to.good_int) {
					fprintf(stderr,
						"%s: could not parse \"%s\" as an int for"
						" bandwidth\n", fn_name, to.valstr);
					err = -1;
					goto exit;
				}
				if ((to.val != 20) && (to.val != 40)) {
					fprintf(stderr,
						"%s: invalid bandwidth %d\n",
						fn_name, to.val);
					err = -1;
					goto exit;
				}
				if (to.val == 20)
					chanspec |= WL_CHANSPEC_BW_20;
				else
					chanspec |= WL_CHANSPEC_BW_40;
				bw_set = TRUE;
			}
			if (to.opt == 's') {
				if (!to.good_int) {
					fprintf(stderr,
						"%s: could not parse \"%s\" as an int for"
						" ctl sideband\n", fn_name, to.valstr);
					err = -1;
					goto exit;
				}
				if ((to.val != 1) && (to.val != 0) && (to.val != -1)) {
					fprintf(stderr,
						"%s: invalid ctl sideband %d\n",
						fn_name, to.val);
					err = -1;
					goto exit;
				}
				if (to.val == -1)
					chanspec |= WL_CHANSPEC_CTL_SB_LOWER;
				else if (to.val == 1)
					chanspec |= WL_CHANSPEC_CTL_SB_UPPER;
				else
					chanspec |= WL_CHANSPEC_CTL_SB_NONE;
				ctl_sb_set = TRUE;
			}
		}

		/* set ctl sb to 20 if not set and 20mhz is selected */
		if (!ctl_sb_set && CHSPEC_IS20(chanspec)) {
			chanspec |= WL_CHANSPEC_CTL_SB_NONE;
			ctl_sb_set = TRUE;
		}

		if (ch_set && band_set && bw_set && ctl_sb_set) {
			err = wl_iovar_setint(wl, cmd->name, (int)chanspec);
		} else {
			if (!ch_set)
				fprintf(stderr, "%s: you need to set a channel,"
					" '-c <ch>'\n", fn_name);
			if (!band_set)
				fprintf(stderr, "%s: you need to set a band,"
					" '-b <5|2>'\n", fn_name);
			if (!bw_set)
				fprintf(stderr, "%s: you need to set a bandwidth,"
					" '-w <20|40>'\n", fn_name);
			if (!ctl_sb_set)
				fprintf(stderr, "%s: you need to set a ctl sideband,"
					  " '-s <-1|0|1>'\n", fn_name);
			err = -1;
		}
	}

	if (!err)
		printf("Chanspec set to 0x%x\n", chanspec);

exit:
	return err;
}

int
wl_ether_atoe(const char *a, struct ether_addr *n)
{
	char *c = (char *) (uintptr)a;
	int i = 0;

	memset(n, 0, ETHER_ADDR_LEN);
	for (;;) {
		n->octet[i++] = (unsigned char) strtoul(c, &c, 16);
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
	}
	return (i == ETHER_ADDR_LEN);
}

char *
wl_ether_etoa(const struct ether_addr *n)
{
	static char etoa_buf[ETHER_ADDR_LEN * 3];
	char *c = etoa_buf;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", n->octet[i] & 0xff);
	}
	return etoa_buf;
}

int
wl_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len)
{
	int i, c;
	char *p = ssid_buf;

	if (ssid_len > 32) ssid_len = 32;

	for (i = 0; i < ssid_len; i++) {
		c = (int)ssid[i];
		if (c == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (isprint((uchar)c)) {
			*p++ = (char)c;
		} else {
			p += sprintf(p, "\\x%02X", c);
		}
	}
	*p = '\0';

	return p - ssid_buf;
}

/* pretty hex print a contiguous buffer */
void
wl_hexdump(uchar *dump_buf, uint nbytes)
{
	char line[256];
	char* p;
	uint i;

	if (nbytes == 0) {
		printf("\n");
		return;
	}

	p = line;
	for (i = 0; i < nbytes; i++) {
		if (i % 16 == 0 && nbytes > 16) {
			p += sprintf(p, "%04d: ", i);	/* line prefix */
		}
		p += sprintf(p, "%02x ", dump_buf[i]);
		if (i % 16 == 15) {
			printf("%s\n", line);		/* flush line */
			p = line;
		}
	}

	/* flush last partial line */
	if (p != line)
		printf("%s\n", line);
}

static int
wl_plcphdr(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int val;

	if (!*++argv) {
		if ((ret = wl_get(wl, cmd->get, &val, sizeof(int))) < 0)
			return ret;
		if (val == WLC_PLCP_AUTO)
			printf("long");
		else if (val == WLC_PLCP_SHORT)
			printf("auto");
		else if (val == WLC_PLCP_LONG)
			printf("debug");
		else
			printf("unknown");
		printf("\n");
		return 0;
	} else {
		if (!stricmp(*argv, "long"))
			val = WLC_PLCP_AUTO;
		else if (!stricmp(*argv, "auto"))
			val = WLC_PLCP_SHORT;
		else if (!stricmp(*argv, "debug"))
			val = WLC_PLCP_LONG;
		else
			return -1;
		return wl_set(wl, cmd->set, &val, sizeof(int));
	}
}

/* WLC_GET_RADIO and WLC_SET_RADIO in driver operate on radio_disabled which
 * is opposite of "wl radio [1|0]".  So invert for user.
 * In addition, display WL_RADIO_SW_DISABLE and WL_RADIO_HW_DISABLE bits.
 */
static int
wl_radio(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	uint val;

	if (!*++argv) {
		if (cmd->get < 0)
			return -1;
		if ((ret = wl_get(wl, cmd->get, &val, sizeof(int))) < 0)
			return ret;
		printf("0x%04x\n", val);
		return 0;
	} else {
		if (cmd->set < 0)
			return -1;
		if (!stricmp(*argv, "on"))
			val = WL_RADIO_SW_DISABLE << 16;
		else if (!stricmp(*argv, "off"))
			val = WL_RADIO_SW_DISABLE << 16 | WL_RADIO_SW_DISABLE;
		else
			val = atoi(*argv);
		return wl_set(wl, cmd->set, &val, sizeof(int));
	}
}

static char *
ver2str(unsigned int vms, unsigned int vls)
{
	static char verstr[100];
	unsigned int maj, year, month, day, build;

	maj = (vms >> 16) & 0xFFFF;
	if (maj > 1000) {
		/* it is probably a date... */
		year = (vms >> 16) & 0xFFFF;
		month = vms & 0xFFFF;
		day = (vls >> 16) & 0xFFFF;
		build = vls & 0xFFFF;
		sprintf(verstr, "%d/%d/%d build %d",
			month, day, year, build);
	} else {
		/* it is a tagged release. */
		sprintf(verstr, "%d.%d RC%d.%d",
			(vms>>16)&0xFFFF, vms&0xFFFF,
			(vls>>16)&0xFFFF, vls&0xFFFF);
	}
	return verstr;
}

static int
wl_version(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int bcmerr;
	char *p = NULL;
	char *dump_buf;

	printf("%s\n",
		ver2str((EPI_MAJOR_VERSION << 16)| EPI_MINOR_VERSION,
		(EPI_RC_NUMBER << 16) | EPI_INCREMENTAL_NUMBER));

	dump_buf = malloc(WL_DUMP_BUF_LEN);
	if (dump_buf == NULL) {
		fprintf(stderr, "Failed to allocate dump buffer of %d bytes\n", WL_DUMP_BUF_LEN);
		return -1;
	}
	memset(dump_buf, 0, WL_DUMP_BUF_LEN);

	/* query for 'ver' to get version info */
	ret = wl_iovar_get(wl, "ver", dump_buf, WL_DUMP_BUF_LEN);

	/* if the query is successful, continue on and print the result. */

	/* if the query fails, check for a legacy driver that does not support
	 * the "dump" iovar, and instead issue a WLC_DUMP ioctl.
	 */
	if (ret) {
		wl_iovar_getint(wl, "bcmerror", &bcmerr);
		if (bcmerr == BCME_UNSUPPORTED) {
			ret = wl_get(wl, WLC_DUMP, dump_buf, WL_DUMP_BUF_LEN);
		}
	}

	if (ret) {
		fprintf(stderr, "Error %d on query of driver dump\n", (int)ret);
		free(dump_buf);
		return IOCTL_ERROR;
	}

	/* keep only the first line from the dump buf output */
	p = strchr(dump_buf, '\n');
	if (p)
		*p = '\0';
	printf("%s\n", dump_buf);

	free(dump_buf);

	return 0;
}

static int
wl_rateparam(void *wl, cmd_t *cmd, char **argv)
{
	int val[2];

	if (!*++argv)
		return -1;
	val[0] = atoi(*argv);
	if (!*++argv)
		return -1;
	val[1] = atoi(*argv);
	return wl_set(wl, cmd->set, val, 2 * sizeof(val));
}

/* wl scan
 * -s --ssid=ssid
 * -t T --scan_type=T : [active|passive]
 * --bss_type=T : [infra|bss|adhoc|ibss]
 * -b --bssid=
 * -n --nprobes=
 * -a --active=
 * -p --passive=
 * -h --home=
 * -c --channels=
 */
static int
wl_scan(void *wl, cmd_t *cmd, char **argv)
{
	wl_scan_params_t* params;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);
	int val = 0;
	char key[64];
	int keylen;
	char *p, *eq, *valstr, *endptr;
	char opt;
	bool positional_param;
	bool good_int;
	bool opt_end;
	int err = 0;

	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL) {
		fprintf(stderr, "Error allocating %d bytes for scan params\n", params_size);
		return -1;
	}
	memset(params, 0, params_size);

	params->bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = -1;
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
	params->channel_num = 0;

	/* skip the command name */
	argv++;

	opt_end = FALSE;
	while ((p = *argv) != NULL) {
		argv++;
		positional_param = FALSE;
		memset(key, 0, sizeof(key));
		opt = '\0';
		valstr = NULL;
		good_int = FALSE;

		if (opt_end) {
			positional_param = TRUE;
			valstr = p;
		}
		else if (!strcmp(p, "--")) {
			opt_end = TRUE;
			continue;
		}
		else if (!strncmp(p, "--", 2)) {
			eq = strchr(p, '=');
			if (eq == NULL) {
				fprintf(stderr,
				"wl_scan: missing \" = \" in long param \"%s\"\n", p);
				err = -1;
				goto exit;
			}
			keylen = eq - (p + 2);
			if (keylen > 63) keylen = 63;
			memcpy(key, p + 2, keylen);

			valstr = eq + 1;
			if (*valstr == '\0') {
				fprintf(stderr,
				"wl_scan: missing value after \" = \" in long param \"%s\"\n", p);
				err = -1;
				goto exit;
			}
		}
		else if (!strncmp(p, "-", 1)) {
			opt = p[1];
			if (strlen(p) > 2) {
				fprintf(stderr,
				"wl_scan: only single char options, error on param \"%s\"\n", p);
				err = -1;
				goto exit;
			}
			if (*argv == NULL) {
				fprintf(stderr,
				"wl_scan: missing value parameter after \"%s\"\n", p);
				err = -1;
				goto exit;
			}
			valstr = *argv;
			argv++;
		} else {
			positional_param = TRUE;
			valstr = p;
		}

		/* parse valstr as int just in case */
		if (valstr) {
			val = (int)strtol(valstr, &endptr, 0);
			if (*endptr == '\0') {
				/* not all the value string was parsed by strtol */
				good_int = TRUE;
			}
		}

		if (opt == 's' || !strcmp(key, "ssid") || positional_param) {
			if (strlen(valstr) > 32) {
				fprintf(stderr,
				"SSID arg \"%s\" must be 32 chars or less\n", valstr);
				err = -1;
				goto exit;
			}
			params->ssid.SSID_len = strlen(valstr);
			memcpy(params->ssid.SSID, valstr, params->ssid.SSID_len);
		}
		if (opt == 't' || !strcmp(key, "scan_type")) {
			if (!strcmp(valstr, "active")) {
				params->scan_type = DOT11_SCANTYPE_ACTIVE;
			} else if (!strcmp(valstr, "passive")) {
				params->scan_type = DOT11_SCANTYPE_PASSIVE;
			} else {
				fprintf(stderr,
				"scan_type value should be \"active\" "
				"or \"passive\", but got \"%s\"\n", valstr);
				err = -1;
				goto exit;
			}
		}
		if (!strcmp(key, "bss_type")) {
			if (!strcmp(valstr, "bss") || !strcmp(valstr, "infra")) {
				params->bss_type = DOT11_BSSTYPE_INFRASTRUCTURE;
			} else if (!strcmp(valstr, "ibss") || !strcmp(valstr, "adhoc")) {
				params->bss_type = DOT11_BSSTYPE_INDEPENDENT;
			} else if (!strcmp(valstr, "any")) {
				params->bss_type = DOT11_BSSTYPE_ANY;
			} else {
				fprintf(stderr,
				"bss_type value should be "
				"\"bss\", \"ibss\", or \"any\", but got \"%s\"\n", valstr);
				err = -1;
				goto exit;
			}
		}
		if (opt == 'b' || !strcmp(key, "bssid")) {
			if (!wl_ether_atoe(valstr, &params->bssid)) {
				fprintf(stderr,
				"could not parse \"%s\" as an ethternet MAC address\n", valstr);
				err = -1;
				goto exit;
			}
		}
		if (opt == 'n' || !strcmp(key, "nprobes")) {
			if (!good_int) {
				fprintf(stderr,
				"could not parse \"%s\" as an int for value nprobes\n", valstr);
				err = -1;
				goto exit;
			}
			params->nprobes = val;
		}
		if (opt == 'a' || !strcmp(key, "active")) {
			if (!good_int) {
				fprintf(stderr,
				"could not parse \"%s\" as an int for active dwell time\n",
					valstr);
				err = -1;
				goto exit;
			}
			params->active_time = val;
		}
		if (opt == 'p' || !strcmp(key, "passive")) {
			if (!good_int) {
				fprintf(stderr,
				"could not parse \"%s\" as an int for passive dwell time\n",
					valstr);
				err = -1;
				goto exit;
			}
			params->passive_time = val;
		}
		if (opt == 'h' || !strcmp(key, "home")) {
			if (!good_int) {
				fprintf(stderr,
				"could not parse \"%s\" as an int for home channel dwell time\n",
					valstr);
				err = -1;
				goto exit;
			}
			params->home_time = val;
		}
		if (opt == 'c' || !strcmp(key, "channels")) {
			params->channel_num =
				wl_parse_channel_list(valstr, params->channel_list, WL_NUMCHANNELS);
			if (params->channel_num == -1) {
				fprintf(stderr, "error parsing channel list arg\n");
				err = -1;
				goto exit;
			}
		}
	}

	params_size = WL_SCAN_PARAMS_FIXED_SIZE + params->channel_num * sizeof(uint16);
	err = wl_set(wl, cmd->set, params, params_size);

exit:
	free(params);
	return err;
}

static int
wl_parse_channel_list(char* list_str, uint16* channel_list, int channel_num)
{
	int num;
	int val;
	char* str;
	char* endptr;

	if (list_str == NULL)
		return -1;

	str = list_str;
	num = 0;
	while (*str != '\0') {
		val = (int)strtol(str, &endptr, 0);
		if (endptr == str) {
			fprintf(stderr,
				"could not parse channel number starting at"
				" substring \"%s\" in list:\n%s\n",
				str, list_str);
			return -1;
		}
		str = endptr + strspn(endptr, " ,");

		if (num == channel_num) {
			fprintf(stderr, "too many channels (more than %d) in channel list:\n%s\n",
				channel_num, list_str);
			return -1;
		}

		channel_list[num++] = (uint16)val;
	}

	return num;
}

/* channel info structure */
typedef struct {
	uint	chan;		/* channel number */
	uint	freq;		/* in Mhz */
} chan_info_t;

static chan_info_t chan_info[] = {
	/* B channels */
	{ 1,	2412},
	{ 2,	2417},
	{ 3,	2422},
	{ 4,	2427},
	{ 5,	2432},
	{ 6,	2437},
	{ 7,	2442},
	{ 8,	2447},
	{ 9,	2452},
	{ 10,	2457},
	{ 11,	2462},
	{ 12,	2467},
	{ 13,	2472},
	{ 14,	2484},

	/* A channels */
	/* 11a usa low */
	{ 36,	5180},
	{ 40,	5200},
	{ 44,	5220},
	{ 48,	5240},
	{ 52,	5260},
	{ 56,	5280},
	{ 60,	5300},
	{ 64,	5320},

	/* 11a Europe */
	{ 100,	5500},
	{ 104,	5520},
	{ 108,	5540},
	{ 112,	5560},
	{ 116,	5580},
	{ 120,	5600},
	{ 124,	5620},
	{ 128,	5640},
	{ 132,	5660},
	{ 136,	5680},
	{ 140,	5700},

	/* 11a usa high */
	{ 149,	5745},
	{ 153,	5765},
	{ 157,	5785},
	{ 161,	5805},

	/* 11a japan */
	{ 184,	4920},
	{ 188,	4940},
	{ 192,	4960},
	{ 196,	4980},
	{ 200,	5000},
	{ 204,	5020},
	{ 208,	5040},
	{ 212,	5060},
	{ 216,	5080}
};

uint
freq2channel(uint freq)
{
	int i;

	for (i = 0; i < (int)ARRAYSIZE(chan_info); i++) {
		if (chan_info[i].freq == freq)
			return (chan_info[i].chan);
	}
	return (0);
}

void
dump_rateset(uint8 *rates, uint count)
{
	uint i;
	uint r;
	bool b;

	printf("[ ");
	for (i = 0; i < count; i++) {
		r = rates[i] & 0x7f;
		b = rates[i] & 0x80;
		if (r == 0)
			break;
		printf("%d%s%s ", (r / 2), (r % 2)?".5":"", b?"(b)":"");
	}
	printf("]");
}

/* Helper routine to print the infrastructure mode while pretty printing the BSS list */
static const char *
capmode2str(uint16 capability)
{
	capability &= (DOT11_CAP_ESS | DOT11_CAP_IBSS);

	if (capability == DOT11_CAP_ESS)
		return "Managed";
	else if (capability == DOT11_CAP_IBSS)
		return "Ad Hoc";
	else
		return "<unknown>";
}

/*
 * Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag
 */
static uint8 *
wlu_parse_tlvs(uint8 *tlv_buf, int buflen, uint key)
{
	uint8 *cp;
	int totlen;

	cp = tlv_buf;
	totlen = buflen;

	/* find tagged parameter */
	while (totlen >= 2) {
		uint tag;
		int len;

		tag = *cp;
		len = *(cp +1);

		/* validate remaining totlen */
		if ((tag == key) && (totlen >= (len + 2)))
			return (cp);

		cp += (len + 2);
		totlen -= (len + 2);
	}

	return NULL;
}

static int
wlu_bcmp(const void *b1, const void *b2, int len)
{
	return (memcmp(b1, b2, len));
}

/* Is this body of this tlvs entry a WPA entry? If */
/* not update the tlvs buffer pointer/length */
static bool
wlu_is_wpa_ie(uint8 **wpaie, uint8 **tlvs, uint *tlvs_len)
{
	uint8 *ie = *wpaie;

	/* If the contents match the WPA_OUI and type=1 */
	if ((ie[1] >= 6) && !wlu_bcmp(&ie[2], WPA_OUI "\x01", 4)) {
		return TRUE;
	}

	/* point to the next ie */
	ie += ie[1] + 2;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return FALSE;
}

static void
wl_dump_wpa_rsn_ies(uint8* cp, uint len)
{
	uint8 *parse = cp;
	uint parse_len = len;
	uint8 *wpaie;
	uint8 *rsnie;

	while ((wpaie = wlu_parse_tlvs(parse, parse_len, DOT11_MNG_WPA_ID)))
		if (wlu_is_wpa_ie(&wpaie, &parse, &parse_len))
			break;
	if (wpaie)
		wl_rsn_ie_dump((bcm_tlv_t*)wpaie);

	rsnie = wlu_parse_tlvs(cp, len, DOT11_MNG_RSN_ID);
	if (rsnie)
		wl_rsn_ie_dump((bcm_tlv_t*)rsnie);

	return;
}

static void
wl_rsn_ie_dump(bcm_tlv_t *ie)
{
	int i;
	int rsn;
	wpa_ie_fixed_t *wpa = NULL;
	rsn_parse_info_t rsn_info;
	wpa_suite_t *suite;
	uint8 std_oui[3];
	int unicast_count = 0;
	int akm_count = 0;
	uint16 capabilities;
	uint cntrs;
	int err;

	if (ie->id == DOT11_MNG_RSN_ID) {
		rsn = TRUE;
		memcpy(std_oui, WPA2_OUI, WPA_OUI_LEN);
		err = wl_rsn_ie_parse_info(ie->data, ie->len, &rsn_info);
	} else {
		rsn = FALSE;
		memcpy(std_oui, WPA_OUI, WPA_OUI_LEN);
		wpa = (wpa_ie_fixed_t*)ie;
		err = wl_rsn_ie_parse_info((uint8*)&wpa->version, wpa->length - WPA_IE_OUITYPE_LEN,
		                           &rsn_info);
	}
	if (err || rsn_info.version != WPA_VERSION)
		return;

	if (rsn)
		printf("RSN:\n");
	else
		printf("WPA:\n");

	/* Check for multicast suite */
	if (rsn_info.mcast) {
		printf("\tmulticast cipher: ");
		if (!wlu_bcmp(rsn_info.mcast->oui, std_oui, 3)) {
			switch (rsn_info.mcast->type) {
			case WPA_CIPHER_NONE:
				printf("NONE\n");
				break;
			case WPA_CIPHER_WEP_40:
				printf("WEP64\n");
				break;
			case WPA_CIPHER_WEP_104:
				printf("WEP128\n");
				break;
			case WPA_CIPHER_TKIP:
				printf("TKIP\n");
				break;
			case WPA_CIPHER_AES_OCB:
				printf("AES-OCB\n");
				break;
			case WPA_CIPHER_AES_CCM:
				printf("AES-CCMP\n");
				break;
			default:
				printf("Unknown-%s(#%d)\n", rsn ? "RSN" : "WPA",
				       rsn_info.mcast->type);
				break;
			}
		}
		else {
			printf("Unknown-%02X:%02X:%02X(#%d) ",
			       rsn_info.mcast->oui[0], rsn_info.mcast->oui[1],
			       rsn_info.mcast->oui[2], rsn_info.mcast->type);
		}
	}

	/* Check for unicast suite(s) */
	if (rsn_info.ucast) {
		unicast_count = ltoh16_ua(&rsn_info.ucast->count);
		printf("\tunicast ciphers(%d): ", unicast_count);
		for (i = 0; i < unicast_count; i++) {
			suite = &rsn_info.ucast->list[i];
			if (!wlu_bcmp(suite->oui, std_oui, 3)) {
				switch (suite->type) {
				case WPA_CIPHER_NONE:
					printf("NONE ");
					break;
				case WPA_CIPHER_WEP_40:
					printf("WEP64 ");
					break;
				case WPA_CIPHER_WEP_104:
					printf("WEP128 ");
					break;
				case WPA_CIPHER_TKIP:
					printf("TKIP ");
					break;
				case WPA_CIPHER_AES_OCB:
					printf("AES-OCB ");
					break;
				case WPA_CIPHER_AES_CCM:
					printf("AES-CCMP ");
					break;
				default:
					printf("WPA-Unknown-%s(#%d) ", rsn ? "RSN" : "WPA",
					       suite->type);
					break;
				}
			}
			else {
				printf("Unknown-%02X:%02X:%02X(#%d) ",
					suite->oui[0], suite->oui[1], suite->oui[2],
					suite->type);
			}
		}
		printf("\n");
	}
	/* Authentication Key Management */
	if (rsn_info.akm) {
		akm_count = ltoh16_ua(&rsn_info.akm->count);
		printf("\tAKM Suites(%d): ", akm_count);
		for (i = 0; i < akm_count; i++) {
			suite = &rsn_info.akm->list[i];
			if (!wlu_bcmp(suite->oui, std_oui, 3)) {
				switch (suite->type) {
				case RSN_AKM_NONE:
					printf("None ");
					break;
				case RSN_AKM_UNSPECIFIED:
					printf("WPA ");
					break;
				case RSN_AKM_PSK:
					printf("WPA-PSK ");
					break;
				default:
					printf("Unknown-%s(#%d)  ",
					       rsn ? "RSN" : "WPA", suite->type);
					break;
				}
			}
			else {
				printf("Unknown-%02X:%02X:%02X(#%d)  ",
					suite->oui[0], suite->oui[1], suite->oui[2],
					suite->type);
			}
		}
		printf("\n");
	}

	/* Capabilities */
	if (rsn_info.capabilities) {
		capabilities = ltoh16_ua(rsn_info.capabilities);
		printf("\tCapabilities(0x%04x): ", capabilities);
		if (rsn)
			printf("%sPre-Auth, ", (capabilities & RSN_CAP_PREAUTH) ? "" : "No ");

		printf("%sPairwise, ", (capabilities & RSN_CAP_NOPAIRWISE) ? "No " : "");

		cntrs = wl_rsn_ie_decode_cntrs((capabilities & RSN_CAP_PTK_REPLAY_CNTR_MASK) >>
		                               RSN_CAP_PTK_REPLAY_CNTR_SHIFT);

		printf("%d PTK Replay Ctr%s", cntrs, (cntrs > 1)?"s":"");

		if (rsn) {
			cntrs = wl_rsn_ie_decode_cntrs(
				(capabilities & RSN_CAP_GTK_REPLAY_CNTR_MASK) >>
				RSN_CAP_GTK_REPLAY_CNTR_SHIFT);

			printf("%d GTK Replay Ctr%s\n", cntrs, (cntrs > 1)?"s":"");
		} else {
			printf("\n");
		}
	} else {
		printf("\tNo %s Capabilities advertised\n", rsn ? "RSN" : "WPA");
	}

}

/* Validates and parses the RSN or WPA IE contents into a rsn_parse_info_t structure
 * Returns 0 on success, or 1 if the information in the buffer is not consistant with
 * an RSN IE or WPA IE.
 * The buf pointer passed in should be pointing at the version field in either an RSN IE
 * or WPA IE.
 */
static int
wl_rsn_ie_parse_info(uint8* rsn_buf, uint len, rsn_parse_info_t *rsn)
{
	uint16 count;

	memset(rsn, 0, sizeof(rsn_parse_info_t));

	/* version */
	if (len < sizeof(uint16))
		return 1;

	rsn->version = ltoh16_ua(rsn_buf);
	len -= sizeof(uint16);
	rsn_buf += sizeof(uint16);

	/* Multicast Suite */
	if (len < sizeof(wpa_suite_mcast_t))
		return 0;

	rsn->mcast = (wpa_suite_mcast_t*)rsn_buf;
	len -= sizeof(wpa_suite_mcast_t);
	rsn_buf += sizeof(wpa_suite_mcast_t);

	/* Unicast Suite */
	if (len < sizeof(uint16))
		return 0;

	count = ltoh16_ua(rsn_buf);

	if (len < (sizeof(uint16) + count * sizeof(wpa_suite_t)))
		return 1;

	rsn->ucast = (wpa_suite_ucast_t*)rsn_buf;
	len -= (sizeof(uint16) + count * sizeof(wpa_suite_t));
	rsn_buf += (sizeof(uint16) + count * sizeof(wpa_suite_t));

	/* AKM Suite */
	if (len < sizeof(uint16))
		return 0;

	count = ltoh16_ua(rsn_buf);

	if (len < (sizeof(uint16) + count * sizeof(wpa_suite_t)))
		return 1;

	rsn->akm = (wpa_suite_auth_key_mgmt_t*)rsn_buf;
	len -= (sizeof(uint16) + count * sizeof(wpa_suite_t));
	rsn_buf += (sizeof(uint16) + count * sizeof(wpa_suite_t));

	/* Capabilites */
	if (len < sizeof(uint16))
		return 0;

	rsn->capabilities = rsn_buf;

	return 0;
}

static uint
wl_rsn_ie_decode_cntrs(uint cntr_field)
{
	uint cntrs;

	switch (cntr_field) {
	case RSN_CAP_1_REPLAY_CNTR:
		cntrs = 1;
		break;
	case RSN_CAP_2_REPLAY_CNTRS:
		cntrs = 2;
		break;
	case RSN_CAP_4_REPLAY_CNTRS:
		cntrs = 4;
		break;
	case RSN_CAP_16_REPLAY_CNTRS:
		cntrs = 16;
		break;
	default:
		cntrs = 0;
		break;
	}

	return cntrs;
}


void
wl_dump_raw_ie(bcm_tlv_t *ie, uint len)
{
	uint dump_len;

	if (len == 0) {
		return;
	} else if (len == 1) {
		printf("IE header truncated: ID: 0x%02X\n", ie->id);
		return;
	} else if (len < (uint)(ie->len + TLV_HDR_LEN)) {
		printf("IE data truncated: ID: 0x%02X Len: %d\n", ie->id, ie->len);
		dump_len = len - TLV_HDR_LEN;
	} else {
		printf("ID: 0x%02X Len: %d\n", ie->id, ie->len);
		dump_len = ie->len;
	}

	/* choose how to format the data based on data len */
	if (dump_len > 16)
		printf("Data:\n");
	else if (dump_len > 0)
		printf("Data: ");

	if (dump_len > 0)
		wl_hexdump(ie->data, dump_len);

	if (dump_len < ie->len)
		printf("<missing %d bytes>\n", ie->len - dump_len);

	return;
}


/* Pretty print the BSS list */
static void
dump_networks(char *network_buf)
{
	wl_scan_results_t *list = (wl_scan_results_t*)network_buf;
	wl_bss_info_t *bi;
	uint i;

	if (list->count == 0)
		return;
	else if (list->version != WL_BSS_INFO_VERSION &&
	         list->version != LEGACY_WL_BSS_INFO_VERSION) {
		fprintf(stderr, "Sorry, your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION);
		return;
	}

	bi = list->bss_info;
	for (i = 0; i < list->count; i++, bi = (wl_bss_info_t*)((int8*)bi + bi->length)) {
		dump_bss_info(bi);
	}
}

static void
dump_bss_info(wl_bss_info_t *bi)
{
	char ssidbuf[SSID_FMT_BUF_LEN];
	wl_bss_info_107_t *old_bi;
	int mcs_idx = 0;

	/* Convert version 107 to 108 */
	if (bi->version == LEGACY_WL_BSS_INFO_VERSION) {
		old_bi = (wl_bss_info_107_t *)bi;
		bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
		bi->ie_length = old_bi->ie_length;
		bi->ie_offset = sizeof(wl_bss_info_107_t);
	}

	wl_format_ssid(ssidbuf, bi->SSID, bi->SSID_len);

	printf("SSID: \"%s\"\n", ssidbuf);

	printf("Mode: %s\t", capmode2str(bi->capability));
	printf("RSSI: %d dBm\t", bi->RSSI);
	printf("noise: %d dBm\t", bi->phy_noise);
	printf("Channel: %d\n", CHSPEC_CHANNEL(bi->chanspec));

	printf("BSSID: %s\t", wl_ether_etoa(&bi->BSSID));

	printf("Capability: ");
	if (bi->capability & DOT11_CAP_ESS) printf("ESS ");
	if (bi->capability & DOT11_CAP_IBSS) printf("IBSS ");
	if (bi->capability & DOT11_CAP_POLLABLE) printf("Pollable ");
	if (bi->capability & DOT11_CAP_POLL_RQ) printf("PollReq ");
	if (bi->capability & DOT11_CAP_PRIVACY) printf("WEP ");
	if (bi->capability & DOT11_CAP_SHORT) printf("ShortPre ");
	if (bi->capability & DOT11_CAP_PBCC) printf("PBCC ");
	if (bi->capability & DOT11_CAP_AGILITY) printf("Agility ");
	if (bi->capability & DOT11_CAP_SHORTSLOT) printf("ShortSlot ");
	if (bi->capability & DOT11_CAP_CCK_OFDM) printf("CCK-OFDM ");
	printf("\n");

	printf("Supported Rates: ");
	dump_rateset(bi->rateset.rates, bi->rateset.count);
	printf("\n");
	if (bi->ie_length)
		wl_dump_wpa_rsn_ies((uint8 *)(((uint8 *)bi) + bi->ie_offset), bi->ie_length);

	if (bi->version != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap) {
		printf("802.11N Capable:\n");
		printf("\tChanspec: %sGHz channel %d %dMHz (0x%x)\n",
			CHSPEC_IS2G(bi->chanspec)?"2.4":"5", CHSPEC_CHANNEL(bi->chanspec),
			CHSPEC_IS40(bi->chanspec) ? 40 : (CHSPEC_IS20(bi->chanspec) ? 20 : 10),
			bi->chanspec);
		printf("\tControl channel: %d\n", bi->ctl_ch);
		printf("\t802.11N Capabilities: ");
		if (bi->nbss_cap & EWC_CAP_40MHZ)
			printf("40Mhz ");
		printf("\n\tSupported MCS : [ ");
		for (mcs_idx = 0; mcs_idx < (MCSSET_LEN * 8); mcs_idx++)
			if (isset(bi->basic_mcs, mcs_idx))
				printf("%d ", mcs_idx);
		printf("]\n");
	}

	printf("\n");
}

static int
wl_dump_networks(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	char *dump_buf;

	dump_buf = malloc(WL_DUMP_BUF_LEN);
	if (dump_buf == NULL) {
		fprintf(stderr, "Failed to allocate dump buffer of %d bytes\n", WL_DUMP_BUF_LEN);
		return -1;
	}

	ret = wl_get_scan(wl, WLC_SCAN_RESULTS, dump_buf, WL_DUMP_BUF_LEN);
	if (ret == 0)
		dump_networks(dump_buf);

	return ret;
}

static int
wl_dump_chanlist(void *wl, cmd_t *cmd, char **argv)
{
	uint32 chan_buf[WL_NUMCHANNELS + 1];
	wl_uint32_list_t *list;
	int ret;
	uint i;

	list = (wl_uint32_list_t *)chan_buf;
	list->count = WL_NUMCHANNELS;
	ret = wl_get(wl, cmd->get, chan_buf, sizeof(chan_buf));
	if (ret < 0)
		return ret;

	for (i = 0; i < list->count; i++)
		printf("%d ", list->element[i]);
	printf("\n");
	return ret;
}

static int
wl_cur_mcsset(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	uint mcs_idx;
	uint8 *mcsset;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_get(wl, "cur_mcsset", &buf, MCSSET_LEN);
	if (ret < 0)
		return ret;

	mcsset = (uint8*)buf;

	printf("MCS SET : [ ");
	for (mcs_idx = 0; mcs_idx < (MCSSET_LEN * 8); mcs_idx++)
		if (isset(mcsset, mcs_idx))
			printf("%d ", mcs_idx);
	printf("]\n");

	return ret;
}


static int
wl_dump_chanspecs(void *wl, cmd_t *cmd, char **argv)
{
	miniopt_t to;
	const char* fn_name = "wl_dump_chanspecs";
	wl_uint32_list_t *list;
	chanspec_t c = 0, *chanspec;
	int ret, buflen;
	uint i;
	int err, opt_err;
	bool band_set = FALSE, bw_set = FALSE;
	char abbrev[WLC_CNTRY_BUF_SZ] = ""; /* default.. current locale */
	char chspec_str[20];

	memset(buf, 0, WLC_IOCTL_MAXLEN);

	strcpy(buf, "chanspecs");
	buflen = strlen(buf) + 1;

	/* toss the command name */
	argv++;

	/* Validate arguments if any */
	if (*argv) {
		miniopt_init(&to, fn_name, NULL);
		while ((opt_err = miniopt(&to, argv)) != -1) {
			if (opt_err == 1) {
				err = -1;
				goto exit;
			}
			argv += to.consumed;

			if (to.opt == 'b') {
				if (!to.good_int) {
					fprintf(stderr,
					        "%s: could not parse \"%s\" as an int for band\n",
					        fn_name, to.valstr);
					err = -1;
					goto exit;
				}
				if ((to.val != 5) && (to.val != 2)) {
					fprintf(stderr,
					        "%s: invalid band %d\n",
					        fn_name, to.val);
					err = -1;
					goto exit;
				}
				if (to.val == 5)
					c |= WL_CHANSPEC_BAND_5G;
				else
					c |= WL_CHANSPEC_BAND_2G;
				band_set = TRUE;
			}
			if (to.opt == 'w') {
				if (!to.good_int) {
					fprintf(stderr,
					        "%s: could not parse \"%s\" as an int for"
					        " bandwidth\n",
					        fn_name, to.valstr);
					err = -1;
					goto exit;
				}
				if ((to.val != 20) && (to.val != 40)) {
					fprintf(stderr,
					        "%s: invalid bandwidth %d\n",
					        fn_name, to.val);
					err = -1;
					goto exit;
				}
				if (to.val == 20)
					c |= WL_CHANSPEC_BW_20;
				else
					c |= WL_CHANSPEC_BW_40;
				bw_set = TRUE;
			}
			if (to.opt == 'c') {
				if (!to.valstr) {
					fprintf(stderr,
					        "%s: please provide country abbrev \n", fn_name);
					err = -1;
					goto exit;
				}
				strncpy(abbrev, to.valstr, WLC_CNTRY_BUF_SZ - 1);
				abbrev[WLC_CNTRY_BUF_SZ] = '\0';
			}
		}
		if (!bw_set || !band_set) {
			if (!band_set)
				fprintf(stderr, "%s: you need to set a band, '-b <5|2>'\n",
				        fn_name);
			if (!bw_set)
				fprintf(stderr, "%s: you need to set a bandwidth, '-w <20|40>'\n",
				        fn_name);
			err = -1;
			goto exit;
		}
	}

	/* Add chanspec argument */
	chanspec = (chanspec_t *) (buf + buflen);
	*chanspec = c;
	buflen += (sizeof(chanspec_t));

	/* Add country abbrev */
	strncpy(buf + buflen, abbrev, WLC_CNTRY_BUF_SZ);
	buflen += WLC_CNTRY_BUF_SZ;

	/* Add list */
	list = (wl_uint32_list_t *)(buf + buflen);
	list->count = WL_NUMCHANSPECS;
	buflen += sizeof(uint32)*(WL_NUMCHANSPECS + 1);

	ret = wl_get(wl, WLC_GET_VAR, &buf, buflen);
	if (ret < 0)
		return ret;

	list = (wl_uint32_list_t *)buf;
	for (i = 0; i < list->count; i++) {
		c = (chanspec_t)list->element[i];
		wf_chspec_ntoa(c, chspec_str);
		printf("%s (0x%04x)\n", chspec_str, c);
	}
	printf("\n");
	return ret;

exit:
	return err;
}

static int
wl_channels_in_country(void *wl, cmd_t *cmd, char **argv)
{
	wl_channels_in_country_t *cic;
	int ret;
	uint i, len;

	cic = (wl_channels_in_country_t *)buf;
	cic->buflen = sizeof(buf);
	cic->count = 0;

	/* country abbrev must follow */
	if (!*++argv) {
		fprintf(stderr, "missing country abbrev\n");
		return -1;
	}

	len = strlen(*argv);
	if ((len > 3) || (len < 2)) {
		fprintf(stderr, "invalid country abbrev: %s\n", *argv);
		return -1;
	}

	strcpy(cic->country_abbrev, *argv);

	/* band must follow */
	if (!*++argv) {
		fprintf(stderr, "missing band\n");
		return -1;
	}

	if (!stricmp(*argv, "a"))
		cic->band = WLC_BAND_5G;
	else if (!stricmp(*argv, "b"))
		cic->band = WLC_BAND_2G;
	else {
		fprintf(stderr, "unsupported band: %s\n", *argv);
		return -1;
	}

	ret = wl_get(wl, cmd->get, buf, cic->buflen);
	if (ret < 0)
		return ret;

	for (i = 0; i < cic->count; i++)
		printf("%d ", cic->channel[i]);
	printf("\n");

	return ret;
}

static int
wl_get_scan(void *wl, int opc, char *scan_buf, uint buf_len)
{
	wl_scan_results_t *list = (wl_scan_results_t*)scan_buf;
	int ret;

	list->buflen = buf_len;
	ret = wl_get(wl, opc, scan_buf, buf_len);
	if (ret < 0)
		return ret;
	ret = 0;

	if (list->buflen == 0) {
		list->version = 0;
		list->count = 0;
	} else if (list->version != WL_BSS_INFO_VERSION &&
	           list->version != LEGACY_WL_BSS_INFO_VERSION) {
		fprintf(stderr, "Sorry, your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION);
		list->buflen = 0;
		list->count = 0;
	}

	return ret;
}

static int
wl_spect(void *wl, cmd_t *cmd, char **argv)
{
	int ret, spect;
	char *endptr;

	if (!*++argv) {
		if ((ret = wl_get(wl, cmd->get, &spect, sizeof(spect))) < 0) {
			return ret;
		}

		switch (spect) {
		case SPECT_MNGMT_OFF:
			printf("Off\n");
			break;

		case SPECT_MNGMT_LOOSE_11H:
			printf("Loose interpretation of 11h spec - may join non 11h AP.\n");
			break;

		case SPECT_MNGMT_STRICT_11H:
			printf("Strict interpretation of 11h spec - may not join non 11h AP.\n");
			break;

		case SPECT_MNGMT_STRICT_11D:
			printf("802.11d mode\n");
			break;

		case SPECT_MNGMT_LOOSE_11H_D:
			printf("Loose interpretation of 11h+d spec - may join non-11h APs\n");
			break;

		default:
			printf("invalid value 0x%x\n", spect);
			return -1;
			break;
		}
		return (0);
	} else {
		spect = strtol(*argv, &endptr, 0);
		if (*endptr != '\0')
			return (-1);

		if (spect < SPECT_MNGMT_OFF || spect > SPECT_MNGMT_LOOSE_11H_D)
			return (-1);

		return wl_set(wl, cmd->set, &spect, sizeof(spect));
	}
}

static int
wl_status(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	struct ether_addr bssid;
	wlc_ssid_t ssid;
	char ssidbuf[SSID_FMT_BUF_LEN];
	wl_bss_info_t *bi;

	if ((ret = wl_get(wl, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN)) == 0) {
		/* The adapter is associated. */
		*(uint32*)buf = WLC_IOCTL_MAXLEN;
		if ((ret = wl_get(wl, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN)) < 0)
			return ret;

		bi = (wl_bss_info_t*)(buf + 4);
		if (bi->version == WL_BSS_INFO_VERSION ||
		    bi->version == LEGACY_WL_BSS_INFO_VERSION)
			dump_bss_info(bi);
		else
			fprintf(stderr, "Sorry, your driver has bss_info_version %d "
				"but this program supports only version %d.\n",
				bi->version, WL_BSS_INFO_VERSION);
	} else {
		printf("Not associated. Last associated with ");

		if ((ret = wl_get(wl, WLC_GET_SSID, &ssid, sizeof(wlc_ssid_t))) < 0) {
			printf("\n");
			return ret;
		}

		wl_format_ssid(ssidbuf, ssid.SSID, ssid.SSID_len);
		printf("SSID: \"%s\"\n", ssidbuf);
	}

	return 0;
}

static int
wl_deauth_rc(void *wl, cmd_t *cmd, char **argv)
{
	scb_val_t scb_val;
	int ret;

	if (!*++argv) {
		fprintf(stderr, "STA MAC must be specified\n");
		ret = -1;

	} else if (!wl_ether_atoe(*argv, &scb_val.ea)) {
		fprintf(stderr, "Malformed STA MAC parameter\n");
		ret = -1;

	} else if (!*++argv) {
		/* No reason code furnished, so driver will use its default */
		ret = wl_set(wl, WLC_SCB_DEAUTHENTICATE, &scb_val.ea,
			ETHER_ADDR_LEN);

	} else {
		scb_val.val = (uint32)strtoul(*argv, NULL, 0);
		ret = wl_set(wl, cmd->set, &scb_val, sizeof(scb_val));
	}
	return ret;
}

static int
wl_wpa_auth(void *wl, cmd_t *cmd, char **argv)
{
	int bsscfg_idx = 0;
	int consumed;
	int wpa_auth;
	int ret = 0;
	int i;
	static struct {
		int val;
		const char *name;
	} auth_mode[] =
		  /* Keep the numeric values in the staticly initialized
		   * help string consistent.  Unfortunately, there isn't
		   * an automatic way for that.
		   */
		{{WPA_AUTH_NONE,	"WPA-NONE"},
		 {WPA_AUTH_UNSPECIFIED,	"WPA-802.1x"},
		 {WPA_AUTH_PSK,		"WPA-PSK"},
#ifdef	BCMWPA2
		 {WPA2_AUTH_UNSPECIFIED, "WPA2-802.1x"},
		 {WPA2_AUTH_PSK,	"WPA2-PSK"},
#endif
		 {WPA_AUTH_DISABLED,	"disabled"}};

	/* skip the command name */
	argv++;

	/* parse a bsscfg_idx option if present */
	if ((ret = wl_cfg_option(argv, cmd->name, &bsscfg_idx, &consumed)) != 0)
		return ret;

	argv += consumed;

	if (!*argv) {
		/* no arg, so this is a GET. */
		const char *mode_name;

		if (!consumed)
			ret = wl_iovar_getint(wl, "wpa_auth", &wpa_auth);
		else
			ret = wl_bssiovar_getint(wl, "wpa_auth", bsscfg_idx, &wpa_auth);

		if (ret < 0)
			return ret;

		mode_name = "Illegal";

		/* Show all AKM suites enabled */
		printf("0x%x ", wpa_auth);

		if (wpa_auth == WPA_AUTH_DISABLED)
			printf("Disabled\n");

		for (i = 0; i < (int)ARRAYSIZE(auth_mode); i++) {
			if (wpa_auth & auth_mode[i].val)
				printf(" %s", auth_mode[i].name);
		}

		printf("\n");
		return ret;


	} else {
		/* there's an arg, so this is a SET. */
		ret = 1;

		/* Validate the user input range */
		if (isdigit((int)*argv[0])) {
			unsigned int range = 0;

			/* param is a number; look for value in the list */
			wpa_auth = strtoul(*argv, NULL, 0);

			/* Validate the user input range */

			for (i = 0; i < (int)ARRAYSIZE(auth_mode); i++)
				range |= auth_mode[i].val;

			range = (~range) & 0xFFFF;

			if (range & wpa_auth) {
				ret = 1;
				goto usage;
			} else {
				ret = 0;
			}

		} else {

			int arg_count = 0;
			char** p_argv;
			int j = 0;
			unsigned int range = 0;

			wpa_auth = 0;
			p_argv = argv;

			for (i = 0; i < (int)ARRAYSIZE(auth_mode); i++)
				range |= auth_mode[i].val;

			range = (~range) & (0xFFFF);

			while (*p_argv) {
				arg_count++;
				p_argv++;
				}

			p_argv = argv;

			for (j = 0; j < arg_count; j++) {
				bool found = FALSE;

				argv = p_argv + j;

				/* treat param as string to be matched in list */
				for (i = 0; i < (int)ARRAYSIZE(auth_mode); i++) {
					if (!stricmp(auth_mode[i].name, *argv)) {

						found = TRUE;
						wpa_auth |= auth_mode[i].val;
						ret = 0;

						/* traverse the list */
						argv++;
						if (!*argv)
							break;
					}
				}

				if ((found == FALSE) || (range & wpa_auth))
					goto usage;
			}

		}
		if (ret)
			fprintf(stderr, "%s is not a valid WPA auth mode\n", *argv);
		else {
			if (!consumed)
				ret = wl_iovar_setint(wl, "wpa_auth", wpa_auth);
			else
				ret = wl_bssiovar_setint(wl, "wpa_auth", bsscfg_idx, wpa_auth);
		}
	}

	return ret;

usage:
	fprintf(stderr, "Inavlid user argument.\n");
	fprintf(stderr, "Values may be a bitvector or list of names from the set.\n");

	for (i = 0; i < (int)ARRAYSIZE(auth_mode); i++) {
		fprintf(stderr, "\n0x%04x  %s", auth_mode[i].val, auth_mode[i].name);
	}

	printf("\n");
	return ret;
}

static int
wl_set_pmk(void *wl, cmd_t *cmd, char **argv)
{
	wsec_pmk_t psk;
	size_t key_len;

	if (!*++argv) {
		return -1;
	}
	key_len = strlen(*argv);
	if (key_len < WSEC_MIN_PSK_LEN || key_len > WSEC_MAX_PSK_LEN) {
		fprintf(stderr, "passphrase must be between %d and %d characters long\n",
		       WSEC_MIN_PSK_LEN, WSEC_MAX_PSK_LEN);
		return -1;
	}
	psk.key_len = (ushort) key_len;
	psk.flags = WSEC_PASSPHRASE;
	memcpy(psk.key, *argv, key_len);
	return wl_set(wl, cmd->set, &psk, sizeof(psk));
}

static int
wl_wsec(void *wl, cmd_t *cmd, char **argv)
{
	int wsec;
	int bsscfg_idx = 0;
	int consumed;
	char *endptr;
	int error;

	argv++;

	/* parse a bsscfg_idx option if present */
	if ((error = wl_cfg_option(argv, "wsec", &bsscfg_idx, &consumed)) != 0)
		return error;

	argv += consumed;

	if (!*argv) {
		/* This is a GET */
		if (consumed == 0)
			error = wl_get(wl, WLC_GET_WSEC, &wsec, sizeof(uint32));
		else
			error = wl_bssiovar_getint(wl, "wsec", bsscfg_idx, &wsec);

		if (!error)
			wl_printint(wsec);
	} else {
		/* This is a SET */
		if (!stricmp(*argv, "off"))
			wsec = 0;
		else {
			wsec = strtol(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}
		}

		if (consumed == 0)
			error = wl_set(wl, WLC_SET_WSEC, &wsec, sizeof(uint32));
		else
			error = wl_bssiovar_setint(wl, "wsec", bsscfg_idx, wsec);
	}

	return error;
}

static int
parse_wep(char **argv, wl_wsec_key_t *key)
{
	char hex[] = "XX";
	unsigned char *data = key->data;
	char *keystr = *argv;

	switch (strlen(keystr)) {
	case 5:
	case 13:
	case 16:
		key->len = strlen(keystr);
		memcpy(data, keystr, key->len + 1);
		break;
	case 12:
	case 28:
	case 34:
	case 66:
		/* strip leading 0x */
		if (!strnicmp(keystr, "0x", 2))
			keystr += 2;
		else
			return -1;
		/* fall through */
	case 10:
	case 26:
	case 32:
	case 64:
		key->len = strlen(keystr) / 2;
		while (*keystr) {
			strncpy(hex, keystr, 2);
			*data++ = (char) strtoul(hex, NULL, 16);
			keystr += 2;
		}
		break;
	default:
		return -1;
	}

	switch (key->len) {
	case 5:
		key->algo = CRYPTO_ALGO_WEP1;
		break;
	case 13:
		key->algo = CRYPTO_ALGO_WEP128;
		break;
	case 16:
		/* default to AES-CCM */
		key->algo = CRYPTO_ALGO_AES_CCM;
		break;
	case 32:
		key->algo = CRYPTO_ALGO_TKIP;
		break;
	default:
		return -1;
	}

	/* Set as primary key by default */
	key->flags |= WL_PRIMARY_KEY;

	/* Get options */
	while (*++argv) {
		if (!strnicmp("ccm", *argv, 3) && key->len == 16)
			key->algo = CRYPTO_ALGO_AES_CCM;
		else if (!strnicmp("ocb", *argv, 3) && key->len == 16)
			key->algo = CRYPTO_ALGO_AES_OCB_MPDU;
		else if (!strnicmp("notx", *argv, 4))
			key->flags &= ~WL_PRIMARY_KEY;
		else if (!wl_ether_atoe(*argv, &key->ea))
			memset(&key->ea, 0, ETHER_ADDR_LEN);
	}

	return 0;
}

static int
wl_primary_key(void *wl, cmd_t *cmd, char **argv)
{
	int i, val, ret = 0;

	if (!*++argv) {
		i = 0;
		do {
			val = i;
			if (wl_get(wl, cmd->get, &val, sizeof(val)) < 0) {
				return -1;
			}
			if (val == TRUE) {
				printf("Key %d is primary\n", i);
				return 0;
			}
		} while (++i < DOT11_MAX_DEFAULT_KEYS);
		printf("No primary key set\n");

	} else {
		val = atoi(*argv);
		ret = wl_set(wl, cmd->set, &val, sizeof(val));
	}
	return ret;
}

static int
wl_addwep(void *wl, cmd_t *cmd, char **argv)
{
	wl_wsec_key_t key;
	int bsscfg_idx = 0;
	int consumed;
	int error;

	memset(&key, 0, sizeof(key));

	argv++;

	/* parse a bsscfg_idx option if present */
	if ((error = wl_cfg_option(argv, "addwep", &bsscfg_idx, &consumed)) != 0)
		return error;

	argv += consumed;

	/* GET operation not allowed */
	if (!*argv)
		return -1;

	key.index = atoi(*argv++);

	if (!*argv) {
		fprintf(stderr, "No key specified\n");
		return -1;
	}
	if (parse_wep(argv, &key))
		return -1;

	if (consumed == 0) {
		error = wl_set(wl, cmd->set, &key, sizeof(key));
	} else {
		error = wl_bssiovar_setbuf(wl, "wsec_key", bsscfg_idx,
			&key, sizeof(key), buf, WLC_IOCTL_MAXLEN);
	}

	return error;
}

static int
wl_rmwep(void *wl, cmd_t *cmd, char **argv)
{
	wl_wsec_key_t key;
	int bsscfg_idx = 0;
	int consumed;
	int error;

	memset(&key, 0, sizeof(key));

	argv++;

	/* parse a bsscfg_idx option if present */
	if ((error = wl_cfg_option(argv, "rmwep", &bsscfg_idx, &consumed)) != 0)
		return error;

	argv += consumed;

	/* GET operation not allowed */
	if (!*argv)
		return -1;

	key.index = atoi(*argv++);

	if (*argv) {
		if (!(wl_ether_atoe(*argv, &key.ea)))
			return -1;
	}

	if (consumed == 0) {
		error = wl_set(wl, cmd->set, &key, sizeof(key));
	} else {
		error = wl_var_setbuf(wl, "wsec_key", &key, sizeof(key));
	}

	return error;
}

static struct {
	uint value;
	const char *string;
} wsec_test[] = {
	{WSEC_GEN_MIC_ERROR, 	"mic_error"},
	{WSEC_GEN_REPLAY, 	"replay"},
	{0,		NULL}
};


static int
wl_wsec_test(void *wl, cmd_t *cmd, char **argv)
{
	wl_wsec_key_t *key;
	int i, len;
	char *endptr, *wsec_buf;
	uint32 val, last_val;

	if (!*++argv)
		goto usage;

	val = strtol(*argv, &endptr, 0);
	if (endptr == *argv) {
		/* the value string was not parsed by strtol */
		for (i = 0; wsec_test[i].value; i++)
			if (stricmp(wsec_test[i].string, *argv) == 0) {
				val = wsec_test[i].value;
				break;
			}
		if (wsec_test[i].value == 0)
			goto usage;
	}
	++argv;

	switch (val) {
	case WSEC_GEN_REPLAY:
	case WSEC_GEN_MIC_ERROR:
		if (!*argv) {
			fprintf(stderr, "insufficient arguments\n");
			return -1;
		}
		len = sizeof(wl_wsec_key_t) + 4;
		wsec_buf = malloc(len);
		*(uint32 *)wsec_buf = val;
		key = (wl_wsec_key_t *)&wsec_buf[4];
		memset(key, 0, sizeof(wl_wsec_key_t));
		/* If it doesn't look like an ether addr, suppose it's a key index */
		if (!(wl_ether_atoe(*argv, &key->ea))) {
			memset(&key->ea, 0, ETHER_ADDR_LEN);
			key->index = atoi(*argv);
		}
		break;
	default:
		goto usage;
		break;
	}

	return wl_set(wl, cmd->set, wsec_buf, len);

usage:
	fprintf(stderr, "wsec test_type may be a number or name from the following set:");
	last_val = 0xffffffff;
	for (i = 0; (val = wsec_test[i].value); i++) {
		if (val != last_val)
			fprintf(stderr, "\n0x%04x %s", val, wsec_test[i].string);
		else
			fprintf(stderr, ", %s", wsec_test[i].string);
		last_val = val;
	}
	fprintf(stderr, "\n");

	return 0;
}

static int
wl_keys(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	uint i, j;
	union {
		int index;
		wl_wsec_key_t key;
	} u;
	int wep_is_on = 0;
	const char *addr;
	int empty_first, empty_last;
	bool empty;

	if ((ret = wl_iovar_getint(wl, "wsec", &wep_is_on)) < 0)
		fprintf(stderr, "Could not query wsec status.\n");

	empty_first = empty_last = -1;

	for (i = 0; ; i++) {	/* The upper limit is not known here. */
		u.index = i;
		ret = wl_get(wl, cmd->get, &u, sizeof(u));
		empty = (ETHER_ISNULLADDR(&u.key.ea) && u.key.algo == CRYPTO_ALGO_OFF);

		if (empty_first != -1 &&
		    (ret < 0 || !empty)) {
			if (empty_first == empty_last)
				printf("%3d: <empty>\n", empty_first);
			else
				printf("%3d - %3d: <empty>\n", empty_first, empty_last);
			empty_first = empty_last = -1;
		}

		if (ret < 0) {
			/* If at least one beyond the defaults could be read,
			 * not knowing the limit must have been the error.
			 */
			return (i >= DOT11_MAX_DEFAULT_KEYS) ? 0 : ret;
		}

		/* Key may not have been set yet */
		if (i < DOT11_MAX_DEFAULT_KEYS)
			addr = "(default)";
		else if (empty) {
			if (empty_first == -1) empty_first = i;
			empty_last = i;
			continue;
		} else
			addr = wl_ether_etoa(&u.key.ea);

		printf("%3d: %-17s Key %d: ", i, addr, u.key.index);

		switch (u.key.algo) {
		case CRYPTO_ALGO_OFF:
			printf("Off");
			break;
		case CRYPTO_ALGO_WEP1:
			printf("WEP1");
			break;
		case CRYPTO_ALGO_WEP128:
			printf("WEP128");
			break;
		case CRYPTO_ALGO_TKIP:
			printf("TKIP");
			break;
		case CRYPTO_ALGO_AES_CCM:
			printf("AES CCM");
			break;
		case CRYPTO_ALGO_AES_OCB_MSDU:
			printf("AES OCB MSDU");
			break;
		case CRYPTO_ALGO_AES_OCB_MPDU:
			printf("AES OCB MPDU");
			break;
		}
		if (wep_is_on && u.key.flags & WL_PRIMARY_KEY)
			printf("*");
		printf("\t");

		if (u.key.len == 0)
			printf("No key present");
		else {
			if (u.key.flags & WL_SOFT_KEY)
				printf("soft ");
			printf("len %d, data 0x", u.key.len);
			for (j = 0; j < u.key.len; j++)
				printf("%02X", u.key.data[j]);

			for (j = 0; j < u.key.len; j++)
				if (!isprint(u.key.data[j]))
					break;
			if (j == u.key.len)
				printf(" (%.*s)", (int)u.key.len, u.key.data);

		}

		printf("\n");
	}

	return 0;
}

static int
wl_tsc(void *wl, cmd_t *cmd, char **argv)
{
	union {
		int32 index;
		uint8 tsc[EAPOL_WPA_KEY_RSC_LEN];
	} u;
	uint32 hi, lo;
	int idx, ret;

	if (!*++argv)
		return -1;
	idx = atoi(*argv);
	if (idx < 0) {
		fprintf(stderr, "Key index %d out of range. Should be positive.\n", idx);
		return -1;
	}
	u.index = idx;
	if ((ret = wl_get(wl, cmd->get, &u, sizeof(u))) < 0)
		return ret;
	lo = u.tsc[0] | (u.tsc[1] << 8) | (u.tsc[2] << 16) | (u.tsc[3] << 24);
	hi = u.tsc[4] | (u.tsc[5] << 8) | (u.tsc[6] << 16) | (u.tsc[7] << 24);

	printf("Key %d TSC: 0x%04x:%08x\n", idx, hi, lo);
	return 0;
}

static int
wl_get_current_power(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	int mimo;
	int i;
	chanspec_t chanspec;
	char chanspec_str[10];
	tx_power_t power;
	bool use_new_power;

	memset(&power, 0, sizeof(power));

	argv++;
	if (*argv)
		fprintf(stderr, "Ignoring arguments for %s\n", cmd->name);

	/* Check for legacy driver by supplying a short buffer
	 * Legacy drivers do not return an error.
	 */
	err = wl_get(wl, cmd->get, &buf, 4);
	use_new_power = (err != 0);

	if (!use_new_power)
		return wl_curpower_legacy(wl);

	if ((err = wl_get(wl, cmd->get, &power, sizeof(power))) < 0)
		return err;

	chanspec = power.chanspec;
	mimo = (power.flags & WL_TX_POWER_F_MIMO);

	printf("Power Control:\t\t %s, %s\n",
	       (power.flags & WL_TX_POWER_F_ENABLED) ? "On" : "Off",
	       (power.flags & WL_TX_POWER_F_HW) ? "HW" : "SW");
	printf("Current channel:\t %s\n",
	       wf_chspec_ntoa(power.chanspec, chanspec_str));
	printf("BSS channel:\t\t %s\n",
	       wf_chspec_ntoa(power.local_chanspec, chanspec_str));
	printf("BSS Local Max:\t\t%2d.%-2d dBm\n",
	       DIV_QUO(power.local_max, 4),
	       DIV_REM(power.local_max, 4));
	printf("BSS Local Constraint:\t%2d.%-2d dB\n",
	       DIV_QUO(power.local_constraint, 4),
	       DIV_REM(power.local_constraint, 4));
	printf("User Target:\t\t%2d.%-2d dBm\n",
	       DIV_QUO(power.user_limit[0], 4),
	       DIV_REM(power.user_limit[0], 4));
	printf("SROM antgain:\t\t 2G: %d.%d dB, 5G: %d.%d dB\n\n",
	       DIV_QUO(power.antgain[0], 4),
	       DIV_REM(power.antgain[0], 4),
	       DIV_QUO(power.antgain[1], 4),
	       DIV_REM(power.antgain[1], 4));

	printf("Regulatory Limits:\n");
	wl_txpwr_array_print(power.reg_limit, CHSPEC_IS2G(chanspec), mimo);
	printf("\n");

	printf("Board Limits:\n");
	wl_txpwr_array_print(power.board_limit, CHSPEC_IS2G(chanspec), mimo);
	printf("\n");

	printf("Power Target:\n");
	wl_txpwr_array_print(power.target, CHSPEC_IS2G(chanspec), mimo);
	printf("\n");

	/* print the different power estimate combinations */
	if (mimo) {
		printf("Last est. power:\t");
		for (i = 0; i < power.rf_cores; i++)
			printf("%d.%d  ",
			       DIV_QUO(power.est_Pout[i], 4),
			       DIV_REM(power.est_Pout[i], 4));
		printf("\n");
	} else {
		printf("Last est. power:\t%d.%d dBm\n",
		       DIV_QUO(power.est_Pout[0], 4),
		       DIV_REM(power.est_Pout[0], 4));
	}

	if (!mimo && CHSPEC_IS2G(chanspec)) {
		printf("Last CCK est. power:\t%d.%d dBm\n",
		       DIV_QUO(power.est_Pout_cck, 4),
		       DIV_REM(power.est_Pout_cck, 4));
	}

	return err;
}

static void
wl_txpwr_array_print(uint8 *pwr, int cck, int mimo)
{
	int newline = TRUE;

	/* CCK rates */
	if (cck)
		wl_txpwr_range_print(pwr, WL_TX_POWER_CCK_FIRST, WL_TX_POWER_CCK_NUM,
		                     "CCK", &newline);

	/* OFDM rates */
	wl_txpwr_range_print(pwr, WL_TX_POWER_OFDM_FIRST, WL_TX_POWER_OFDM_NUM, "OFDM", &newline);

	if (mimo) {
		/* MCS 20MHz rates */
		wl_txpwr_range_print(pwr, WL_TX_POWER_MCS20_FIRST, WL_TX_POWER_MCS20_NUM,
		                     "MCS 20MHz", &newline);

		/* MCS 40MHz rates */
		wl_txpwr_range_print(pwr, WL_TX_POWER_MCS40_FIRST, WL_TX_POWER_MCS40_NUM,
		                     "MCS 40MHz", &newline);
	}

	if (!newline)
		printf("\n");
}

static void
wl_txpwr_range_print(uint8 *pwr, int start, int count, const char* label, int *newline)
{
	if (wl_array_uniform(pwr, start, count)) {
		/* need a space for abbreviated printout */
		if (!*newline)
			printf("  ");
		printf("%s: %2d.%-2d", label,
		       DIV_QUO(pwr[start], 4),
		       DIV_REM(pwr[start], 4));
		*newline = FALSE;
	} else {
		/* need a newline for a full row printout */
		if (!*newline)
			printf("\n");
		printf("%s: ", label);
		wl_txpwr_row_print(pwr, start, count);
		printf("\n");
		*newline = TRUE;
	}
}

static void
wl_txpwr_row_print(uint8 *pwr, int start, int count)
{
	int i, rate;

	for (i = 0, rate = start; i < count; i++, rate++)
		printf("%2d.%-2d ",
		       DIV_QUO(pwr[rate], 4),
		       DIV_REM(pwr[rate], 4));
}

/* return TRUE if all the values in the array are uniformly the same */
static int
wl_array_uniform(uint8 *pwr, int start, int count)
{
	int i, rate;

	for (i = 1, rate = start + 1; i < count; i++, rate++)
		if (pwr[rate] != pwr[rate - 1])
			return FALSE;

	return TRUE;
}

static int
wl_curpower_legacy(void *wl)
{
	int err;
	int val;
	int i;
	int32 flags;
	bool valid;
	chanspec_t chanspec;
	char chanspec_str[10];
	tx_power_legacy_t power;
	int eirp;

	err = wl_iovar_getint(wl, "eirp", &eirp);
	if (err)
		return err;

	if ((err = wl_get(wl, WLC_GET_UCFLAGS, &flags, sizeof(flags))) < 0)
		valid = FALSE;
	else
		valid = TRUE;

	if ((err = wl_iovar_getint(wl, "chanspec", &val)) < 0)
		return err;
	chanspec = (chanspec_t)val;
	wf_chspec_ntoa(chanspec, chanspec_str);

	if ((err = wl_get(wl, WLC_CURRENT_PWR, &power, sizeof(power))) < 0)
		return err;

	printf("Current channel:\t\t %s\n",
	       wf_chspec_ntoa(chanspec, chanspec_str));
	printf("User Target:\t\t\t%2d.%-2d dBm\n",
	       DIV_QUO(power.txpwr_band_max[0], 4),
	       DIV_REM(power.txpwr_band_max[0], 4));
	printf("Regulatory Local Max:\t\t%2d.%-2d dBm\n",
	       DIV_QUO(power.txpwr_local_max, 4),
	       DIV_REM(power.txpwr_local_max, 4));
	printf("Regulatory Local Constraint:\t%2d.%-2d dB\n",
	       DIV_QUO(power.txpwr_local_constraint, 4),
	       DIV_REM(power.txpwr_local_constraint, 4));
	printf("Antgain used in Channel Max:\t %s\n",
	       (eirp & 1) ?
	       "Yes, channel is EIRP" : "No, channel is Conducted");
	printf("Hardware Power Control:\t\t ");
	if (valid)
		printf("%s\n", flags & 0x800000 ? "On" : "Off");
	else
		printf("Unknown - driver must be up\n");
	printf("Regulatory Channel Max:\t\t%2d.%-2d dBm\n",
	       DIV_QUO(power.txpwr_chan_reg_max, 4),
	       DIV_REM(power.txpwr_chan_reg_max, 4));
	printf("SROM antgain:\t\t\t 2G: %d.%d dB, 5G: %d.%d dB\n\n",
	       DIV_QUO(power.txpwr_antgain[0], 4),
	       DIV_REM(power.txpwr_antgain[0], 4),
	       DIV_QUO(power.txpwr_antgain[1], 4),
	       DIV_REM(power.txpwr_antgain[1], 4));

	printf("Min of Reg & Local Limits:\n");
	printf(" CCK:\t ");
	for (i = 0; i < 4; i++)
		printf("%d.%d ",
		       DIV_QUO(power.txpwr_limit[i], 4),
		       DIV_REM(power.txpwr_limit[i], 4));
	printf("\nOFDM:\t ");
	for (; i < NUM_PWRCTRL_RATES; i++)
		printf("%d.%d ",
		       DIV_QUO(power.txpwr_limit[i], 4),
		       DIV_REM(power.txpwr_limit[i], 4));
	printf("\n\n");

	/* band specific info */
	if (CHSPEC_IS2G(chanspec)) {
		/* 2G band */
		printf("Last B phy CCK est. power:\t%2d.%-2d dBm\n",
		       DIV_QUO(power.txpwr_est_Pout[0], 4),
		       DIV_REM(power.txpwr_est_Pout[0], 4));
		printf("Last B phy OFDM est. power:\t%2d.%-2d dBm\n",
		       DIV_QUO(power.txpwr_est_Pout_gofdm, 4),
		       DIV_REM(power.txpwr_est_Pout_gofdm, 4));

		printf("\n");
		printf("Srom limit B/G:\n");
		printf(" CCK:\t ");
		for (i = 0; i < 4; i++)
			printf("%d.%d ", DIV_QUO(power.txpwr_bphy_cck_max[i], 4),
			       DIV_REM(power.txpwr_bphy_cck_max[i], 4));
		printf("\nOFDM:\t ");
		for (; i < NUM_PWRCTRL_RATES; i++)
			printf("%d.%d ", DIV_QUO(power.txpwr_bphy_cck_max[i], 4),
			       DIV_REM(power.txpwr_bphy_cck_max[i], 4));
		printf("\n");

		printf("Last B phy target power:\n");
		printf(" CCK:\t ");
		for (i = 0; i < 4; i++)
			printf("%d.%d ", DIV_QUO(power.txpwr_target[0][i], 4),
			       DIV_REM(power.txpwr_target[0][i], 4));
		printf("\nOFDM:\t ");
		for (; i < NUM_PWRCTRL_RATES; i++)
			printf("%d.%d ", DIV_QUO(power.txpwr_target[0][i], 4),
			       DIV_REM(power.txpwr_target[0][i], 4));
		printf("\n");
	} else {
		/* 5G band */
		printf("Last A phy est. power:\t\t%2d.%-2d dBm\n",
		       DIV_QUO(power.txpwr_est_Pout[1], 4),
		       DIV_REM(power.txpwr_est_Pout[1], 4));
		printf("Srom limit A:\n");
		printf("OFDM:\t ");
		for (i = 4; i < NUM_PWRCTRL_RATES; i++)
			printf("%d.%d ", DIV_QUO(power.txpwr_aphy_max[i], 4),
			       DIV_REM(power.txpwr_aphy_max[i], 4));
		printf("\n");

		printf("Last A phy target power:\n");
		printf("OFDM:\t ");
		for (i = 4; i < NUM_PWRCTRL_RATES; i++)
			printf("%d.%d ", DIV_QUO(power.txpwr_target[1][i], 4),
			       DIV_REM(power.txpwr_target[1][i], 4));
		printf("\n");
	}

	return err;
}

static int
wl_get_instant_power(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	tx_inst_power_t *power;
	uint band_list[3];

	strcpy(buf, "txinstpwr");
	if ((ret = wl_get(wl, WLC_GET_VAR, &buf, WLC_IOCTL_MAXLEN)) < 0) {
		return ret;
	}

	power = (tx_inst_power_t *)buf;
	/* Make the most of the info returned in band_list!
	 * b/g and a
	 * b/g-uni
	 * a-uni
	 * NOTE: NO a and b/g case ...
	 */
	if ((ret = wl_get(wl, WLC_GET_BANDLIST, band_list, sizeof(band_list))) < 0)
		return (ret);

	/* If B/G is present it's always the lower index */
	if (band_list[1] == WLC_BAND_2G) {
			printf("Last B phy CCK est. power:\t%2d.%d dBm\n",
			       DIV_QUO(power->txpwr_est_Pout[0], 4),
			       DIV_REM(power->txpwr_est_Pout[0], 4));
			printf("Last B phy OFDM est. power:\t%2d.%d dBm\n",
			       DIV_QUO(power->txpwr_est_Pout_gofdm, 4),
			       DIV_REM(power->txpwr_est_Pout_gofdm, 4));

			printf("\n");
	}

	/* A band */
	if (band_list[1] == WLC_BAND_5G || (band_list[0] > 1 && band_list[2] == WLC_BAND_5G)) {
		printf("Last A phy est. power:\t\t%2d.%d dBm\n",
		       DIV_QUO(power->txpwr_est_Pout[1], 4),
		       DIV_REM(power->txpwr_est_Pout[1], 4));
	}

	return ret;
}

static int
wl_evm(void *wl, cmd_t *cmd, char **argv)
{
	int val[3];

	/* Get channel */
	if (!*++argv) {
		fprintf(stderr, "Need to specify at least one parameter\n");
		return -1;
	}

	if (!stricmp(*argv, "off"))
		val[0] = 0;
	else
		val[0] = atoi(*argv);

	/* set optional parameters to default */
	val[1] = 4;	/* rate in 500Kb units */
	val[2] = 0;	/* This is ignored */

	/* Get optional rate and convert to 500Kb units */
	if (*++argv)
		val[1] = rate_string2int(*argv);

	return wl_set(wl, cmd->set, val, sizeof(val));
}

static int
wl_join(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	wlc_ssid_t ssid;
	wl_wsec_key_t key;
	int wsec = 0, auth = 0, infra = 1;
	int wpa_auth = -1;
	char* cmd_name;

	cmd_name = *argv++;

	/* verify that SSID was specified and is a valid length */
	if (!*argv || (strlen(*argv) > DOT11_MAX_SSID_LEN))
		return -1;

	ssid.SSID_len = strlen(*argv);
	memcpy(ssid.SSID, *argv, ssid.SSID_len);

	/* get current wsec */
	if (wl_iovar_getint(wl, "wsec", &wsec) < 0)
		wsec = 0;

	while (*++argv) {
		/* specified wep key */
		memset(&key, 0, sizeof(wl_wsec_key_t));
		if (!stricmp(*argv, "wepkey") || !stricmp(*argv, "wep") || !stricmp(*argv, "key")) {
			if (!*++argv)
				return -1;
			key.index = 0;
			if (parse_wep(argv, &key))
				return -1;
			if ((ret = wl_set(wl, WLC_SET_KEY, &key, sizeof(wl_wsec_key_t))) < 0)
				return ret;
			wsec |= WEP_ENABLED;
		}
		/* specified infrastructure mode */
		else if (!stricmp(*argv, "imode") ||
		         !stricmp(*argv, "infra") ||
		         !stricmp(*argv, "mode")) {
			if (!*++argv) {
				fprintf(stderr, "%s %s: expected argument after \"infra\" keyword "
				        "but command line ended.\n", av0, cmd_name);
				return -1;
			} else if (!stricmp(*argv, "ibss") ||
			           !stricmp(*argv, "adhoc") ||
			           !stricmp(*argv, "ad-hoc")) {
				infra = 0;
			} else if (!stricmp(*argv, "bss") ||
			           !stricmp(*argv, "managed") ||
			           !strnicmp(*argv, "infra", 5)) {
				infra = 1;
			} else {
				fprintf(stderr, "%s %s: unrecongnized parameter \"%s\" after "
				        "\"infra\" keyword\n", av0, cmd_name, *argv);
				return -1;
			}
		}
		/* specified authentication mode */
		else if (!stricmp(*argv, "amode") || !strnicmp(*argv, "auth", 4)) {
			if (!*++argv)
				return -1;
			if (!stricmp(*argv, "open"))
				auth = 0;
			else if (!stricmp(*argv, "shared"))
				auth = 1;
			else if (!stricmp(*argv, "wpanone"))
				wpa_auth = WPA_AUTH_NONE;
			else if (!stricmp(*argv, "wpa"))
				wpa_auth = WPA_AUTH_UNSPECIFIED;
			else if (!stricmp(*argv, "wpapsk"))
				 wpa_auth = WPA_AUTH_PSK;
#ifdef BCMWPA2
			else if (!stricmp(*argv, "wpa2"))
				wpa_auth = WPA2_AUTH_UNSPECIFIED;
			else if (!stricmp(*argv, "wpa2psk"))
				wpa_auth = WPA2_AUTH_PSK;
#endif
			else
				return -1;
		}
	}

	/* set infrastructure mode */
	if ((ret = wl_set(wl, WLC_SET_INFRA, &infra, sizeof(int))) < 0)
		return ret;

	/* set authentication mode */
	if ((ret = wl_set(wl, WLC_SET_AUTH, &auth, sizeof(int))) < 0)
		return ret;

	/* set wsec mode */
	if ((ret = wl_iovar_setint(wl, "wsec", wsec)) < 0)
		return ret;

	/* set WPA_auth mode if one was given */
	if (wpa_auth != -1 && (ret = wl_set(wl, WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;

	/* set ssid */
	return wl_set(wl, WLC_SET_SSID, &ssid, sizeof(wlc_ssid_t));
}

/* Set or Get the "ssid" iovar, with an optional config index argument:
 *	wl ssid [-C N]|[--cfg=N] ssid
 *
 * Option:
 *	-C N
 *	--cfg=N
 *	--config=N
 *	--configuration=N
 *		specify the config index N
 * If cfg index not given on a set, the WLC_SET_SSID ioctl will be used
 */
static int
wl_ssid(void *wl, cmd_t *cmd, char **argv)
{
	char ssidbuf[SSID_FMT_BUF_LEN];
	wlc_ssid_t ssid;
	int bsscfg_idx = 0;
	int consumed;
	int error;

	argv++;

	/* parse a bsscfg_idx option if present */
	if ((error = wl_cfg_option(argv, "ssid", &bsscfg_idx, &consumed)) != 0)
		return error;

	argv += consumed;

	if (*argv == NULL) {
		if (consumed == 0) {
			/* no config index, use WLC_GET_SSID on the interface */
			error = wl_get(wl, WLC_GET_SSID, &ssid, sizeof(ssid));
		} else {
			/* use "ssid" iovar since a config option was given */
			error = wl_bssiovar_get(wl, "ssid", bsscfg_idx, &ssid, sizeof(ssid));
		}
		if (error < 0)
			return error;

		wl_format_ssid(ssidbuf, ssid.SSID, ssid.SSID_len);
		printf("Current SSID: \"%s\"\n", ssidbuf);
	} else {
		if (strlen(argv[0]) > 32) {
			fprintf(stderr, "SSID arg \"%s\" must be 32 chars or less\n", argv[0]);
			return -1;
		}
		ssid.SSID_len = strlen(argv[0]);
		memcpy(ssid.SSID, argv[0], ssid.SSID_len + 1);

		wl_format_ssid(ssidbuf, ssid.SSID, ssid.SSID_len);
		printf("Setting SSID \"%s\"\n", ssidbuf);

		if (consumed == 0) {
			/* no config index given, use WLC_SET_SSID */
			error = wl_set(wl, WLC_SET_SSID, &ssid, sizeof(wlc_ssid_t));
		} else {
			/* use "ssid" iovar since a config option was given */
			error = wl_bssiovar_set(wl, "ssid", bsscfg_idx, &ssid, sizeof(wlc_ssid_t));
		}
	}
	return error;
}


static int
wl_tssi(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int val;

	if (cmd->get < 0)
		return -1;
	if ((ret = wl_get(wl, cmd->get, &val, sizeof(int))) < 0)
		return ret;

	printf("CCK %d OFDM %d\n", (val & 0xff), (val >> 8) & 0xff);
	return 0;
}

/* Quarter dBm units to mW
 * Table starts at QDBM_OFFSET, so the first entry is mW for qdBm=153
 * Table is offset so the last entry is largest mW value that fits in
 * a uint16.
 */

#define QDBM_OFFSET 153 /* QDBM_OFFSET */
#define QDBM_TABLE_LEN 40 /* QDBM_TABLE_LEN */

/* Smallest mW value that will round up to the first table entry, QDBM_OFFSET.
 * Value is ( mW(QDBM_OFFSET - 1) + mW(QDBM_OFFSET) ) / 2
 */
#define QDBM_TABLE_LOW_BOUND 6493 /* QDBM_TABLE_LOW_BOUND */

/* Largest mW value that will round down to the last table entry,
 * QDBM_OFFSET + QDBM_TABLE_LEN-1.
 * Value is ( mW(QDBM_OFFSET + QDBM_TABLE_LEN - 1) + mW(QDBM_OFFSET + QDBM_TABLE_LEN) ) / 2.
 */
#define QDBM_TABLE_HIGH_BOUND 64938 /* QDBM_TABLE_HIGH_BOUND */

static const uint16 nqdBm_to_mW_map[QDBM_TABLE_LEN] = {
/* qdBm:        +0	+1	+2	+3	+4	+5	+6	+7	*/
/* 153: */      6683,	7079,	7499,	7943,	8414,	8913,	9441,	10000,
/* 161: */      10593,	11220,	11885,	12589,	13335,	14125,	14962,	15849,
/* 169: */      16788,	17783,	18836,	19953,	21135,	22387,	23714,	25119,
/* 177: */      26607,	28184,	29854,	31623,	33497,	35481,	37584,	39811,
/* 185: */      42170,	44668,	47315,	50119,	53088,	56234,	59566,	63096
};

static uint16
wl_qdbm_to_mw(uint8 qdbm)
{
	uint factor = 1;
	int idx = qdbm - QDBM_OFFSET;

	if (idx > QDBM_TABLE_LEN) {
		/* clamp to max uint16 mW value */
		return 0xFFFF;
	}

	/* scale the qdBm index up to the range of the table 0-40
	 * where an offset of 40 qdBm equals a factor of 10 mW.
	 */
	while (idx < 0) {
		idx += 40;
		factor *= 10;
	}

	/* return the mW value scaled down to the correct factor of 10,
	 * adding in factor/2 to get proper rounding.
	 */
	return ((nqdBm_to_mW_map[idx] + factor/2) / factor);
}

static uint8
wl_mw_to_qdbm(uint16 mw)
{
	uint8 qdbm;
	int offset;
	uint mw_uint = mw;
	uint boundary;

	/* handle boundary case */
	if (mw_uint <= 1)
		return 0;

	offset = QDBM_OFFSET;

	/* move mw into the range of the table */
	while (mw_uint < QDBM_TABLE_LOW_BOUND) {
		mw_uint *= 10;
		offset -= 40;
	}

	for (qdbm = 0; qdbm < QDBM_TABLE_LEN-1; qdbm++) {
		boundary = nqdBm_to_mW_map[qdbm] +
			(nqdBm_to_mW_map[qdbm+1] - nqdBm_to_mW_map[qdbm])/2;
		if (mw_uint < boundary) break;
	}

	qdbm += (uint8)offset;

	return (qdbm);
}

#define UNIT_MW		1 /* UNIT_MW */
#define UNIT_QDBM	2 /* UNIT_QDBM */
#define UNIT_DBM	3 /* UNIT_DBM */
static int
wl_txpwr1(void *wl, cmd_t *cmd, char **argv)
{
	int ret, val, new_val = 0, unit;
	char pwr_buf[20];
	uint32 *int_ptr;
	bool override = FALSE;

	strcpy(pwr_buf, "qtxpower");

	if (!*++argv) {
		if (cmd->get < 0)
			return -1;
		if ((ret = wl_get(wl, WLC_GET_VAR, &pwr_buf, strlen(pwr_buf) + 5)) < 0)
			return ret;

		int_ptr = (uint32 *)&pwr_buf[0];
		val = *int_ptr;
		override = (bool)(val & WL_TXPWR_OVERRIDE);
		val &= ~WL_TXPWR_OVERRIDE;
		printf("TxPower is %d qdbm, %d.%d dbm, %d mW  Override is %s\n",
		       val, DIV_QUO(val, 4), DIV_REM(val, 4),
		       wl_qdbm_to_mw((uint8)(MIN(val, 0xff))),
		       override ? "On" : "Off");
		return 0;
	} else {
		/* for set */
		unit = UNIT_DBM;	/* default units */

		/* override can be used in combo with any unit */
		if (!strcmp(*argv, "-o")) {
			override = TRUE;
			if (!*++argv)
				return (-1);
		}

		if (!strcmp(*argv, "-d")) {
			unit = UNIT_DBM;
			argv++;
		}
		else if (!strcmp(*argv, "-q")) {
			unit = UNIT_QDBM;
			argv++;
		}
		else if (!strcmp(*argv, "-m")) {
			unit = UNIT_MW;
			argv++;
		}

		/* override can be used in combo with any unit */
		if (!strcmp(*argv, "-o")) {
			override = TRUE;
			argv++;
		}

		if (!*argv)
			return (-1);

		val = atoi(*argv);

		if (val == -1) {
			val = 127;		/* Max val of 127 qdbm */
			unit = UNIT_QDBM;
		}

		if (val <= 0) {
			return -1;
		}

		switch (unit) {
		case UNIT_MW:
			new_val = wl_mw_to_qdbm((uint16)MIN(val, 0xffff));
			break;
		case UNIT_DBM:
			new_val = val * 4;
			break;
		case UNIT_QDBM:
			new_val = val;
			break;
		}
		int_ptr = (uint32 *)&pwr_buf[strlen(pwr_buf) + 1];
		if (override)
			new_val |= WL_TXPWR_OVERRIDE;
		memcpy(int_ptr, (const void *)&new_val, sizeof(new_val));
		if ((ret = wl_set(wl, WLC_SET_VAR, &pwr_buf, strlen(pwr_buf)+5)) < 0)
			return ret;
		return 0;
	}
}

static int
wl_txpwr(void *wl, cmd_t *cmd, char **argv)
{
	int error;
	int val;
	char *endptr;
	int override;
	const char *name = "qtxpower";
	uint16 mw;

	if (!*++argv) {
		if ((error = wl_iovar_getint(wl, name, &val) < 0))
			return error;

		/* Report power in mw with WL_TXPWR_OVERRIDE
		 * bit indicating the status
		 */
		printf("pwr in mw %d\n", val);
		override = val & WL_TXPWR_OVERRIDE;
		val &= ~WL_TXPWR_OVERRIDE;
		printf("pwr in mw after override adj %d\n", val);
		mw = wl_qdbm_to_mw((uint8)(MIN(val, 0xff)));
		printf("%d\n", mw | override);
		return 0;
	} else {
		if (!strcmp(*argv, "-u")) {
			override = 0;
			argv++;
		} else
			override = WL_TXPWR_OVERRIDE;

		val = strtol(*argv, &endptr, 0);
		if (*endptr != '\0') {
			/* not all the value string was parsed by strtol */
			return -1;
		}

		val = wl_mw_to_qdbm((uint16)MIN(val, 0xffff));

		/* wl command input power will override current power set if told so */
		val |= override;

		return wl_iovar_setint(wl, name, val);
	}
}

static int
wl_get_txpwr_limit(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	uint8 val_qdbm;
	uint16 val_mw;
	tx_power_legacy_t power;

	ret = wl_get(wl, cmd->get, &power, sizeof(power));
	if (ret < 0)
		return ret;

	val_qdbm = MIN(power.txpwr_band_max[0], power.txpwr_local_max);
	val_mw = wl_qdbm_to_mw((uint8)(MIN(val_qdbm, 0xff)));

	printf("%d mW (%d.%d dBm)\n", val_mw, DIV_QUO(val_qdbm, 4), DIV_REM(val_qdbm, 4));

	return ret;
}

static int
wl_atten(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	atten_t atten;
	char *endptr;

	if (!*++argv) {
		if (cmd->get < 0)
			return -1;

		if ((ret = wl_get(wl, cmd->get, &atten, sizeof(atten_t))) < 0)
			return ret;

		printf("tx %s bb/radio/ctl1 %d/%d/%d\n",
		       (atten.auto_ctrl ? "auto" : ""),
			atten.bb, atten.radio, atten.txctl1);

		return 0;
	} else {
		if (cmd->set < 0)
			return -1;

		if (!stricmp(*argv, "auto")) {
			atten.auto_ctrl = WL_ATTEN_PCL_ON;
		}
		else if (!stricmp(*argv, "manual")) {
			atten.auto_ctrl = WL_ATTEN_PCL_OFF;
		}
		else {
			atten.auto_ctrl = WL_ATTEN_APP_INPUT_PCL_OFF;

			atten.bb = (uint16)strtoul(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}

			if (!*++argv)
				return -1;

			atten.radio = (uint16)strtoul(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}

			if (!*++argv)
				return -1;

			atten.txctl1 = (uint16)strtoul(*argv, &endptr, 0);
			if (*endptr != '\0') {
				/* not all the value string was parsed by strtol */
				return -1;
			}

		}

		return wl_set(wl, cmd->set, &atten, sizeof(atten_t));
	}
}

static int
wl_maclist(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	struct maclist *maclist = (struct maclist *) buf;
	struct ether_addr *ea;
	uint i, max = (WLC_IOCTL_MAXLEN - sizeof(int)) / ETHER_ADDR_LEN;
	uint len;

	if (!*++argv) {
		if (cmd->get < 0)
			return -1;
		maclist->count = max;
		if ((ret = wl_get(wl, cmd->get, maclist, WLC_IOCTL_MAXLEN)) < 0)
			return ret;
		for (i = 0, ea = maclist->ea; i < maclist->count && i < max; i++, ea++)
			printf("%s %s\n", cmd->name, wl_ether_etoa(ea));
		return 0;
	} else {
		if (cmd->set < 0)
			return -1;
		/* Clear list */
		maclist->count = 0;
		if (!stricmp(*argv, "none") || !stricmp(*argv, "clear"))
			return wl_set(wl, cmd->set, maclist, sizeof(int));
		/* Get old list */
		maclist->count = max;
		if ((ret = wl_get(wl, cmd->get, maclist, WLC_IOCTL_MAXLEN)) < 0)
			return ret;
		/* Append to old list */
		ea = &maclist->ea[maclist->count];
		while (*argv && maclist->count < max) {
			if (!wl_ether_atoe(*argv, ea)) {
				printf("Problem parsing MAC address \"%s\".\n", *argv);
				return -1;
			}
			maclist->count++;
			ea++;
			argv++;
		}
		/* Set new list */
		len = sizeof(maclist->count) + maclist->count * sizeof(maclist->ea);
		return wl_set(wl, cmd->set, maclist, len);
	}
}

static int
wl_maclist_1(void *wl, cmd_t *cmd, char **argv)
{
	struct maclist *maclist;
	struct ether_addr *ea;
	uint i;
	int ret;

	strcpy(buf, argv[0]);

	if ((ret = wl_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN)) < 0)
		return ret;

	maclist = (struct maclist *)buf;

	for (i = 0, ea = maclist->ea; i < maclist->count; i++, ea++)
		printf("%s %s\n", cmd->name, wl_ether_etoa(ea));
	return 0;
}

static int
wl_out(void *wl, cmd_t *cmd, char **argv)
{
	return wl_set(wl, WLC_OUT, NULL, 0);
}

static int
wl_band(void *wl, cmd_t *cmd, char **argv)
{
	uint band;
	int error;

	error = 0;

	argv++;

	if (*argv == NULL) {	/* get current band */
		if ((error = wl_get(wl, WLC_GET_BAND, &band, sizeof(uint))) < 0)
			return (error);

		if (band == WLC_BAND_AUTO)
			printf("auto\n");
		else if (band == WLC_BAND_5G)
			printf("a\n");
		else if (band == WLC_BAND_2G)
			printf("b\n");
		else
			printf("unrecognized band value %d\n", band);
	} else {		/* set the band */
		if (!stricmp(*argv, "auto"))
			band = WLC_BAND_AUTO;
		else if (!stricmp(*argv, "a"))
			band = WLC_BAND_5G;
		else if (!stricmp(*argv, "b"))
			band = WLC_BAND_2G;
		else {
			printf("unsupported band: %s\n", *argv);
			return (-1);
		}

		error = wl_set(wl, WLC_SET_BAND, &band, sizeof(uint));

	}
	return (error);
}

static int
wl_bandlist(void *wl, cmd_t *cmd, char **argv)
{
	uint list[3];
	int error;
	uint i;

	error = 0;

	argv++;

	if ((error = wl_get(wl, WLC_GET_BANDLIST, list, sizeof(list))) < 0)
		return (error);

	/* list[0] is count, followed by 'count' bands */

	if (list[0] > 2)
		list[0] = 2;

	for (i = 1; i <= list[0]; i++)
		if (list[i] == WLC_BAND_5G)
			printf("a ");
		else if (list[i] == WLC_BAND_2G)
			printf("b ");
		else
			printf("? ");
	printf("\n");

	return (0);
}

static int
wl_phylist(void *wl, cmd_t *cmd, char **argv)
{
	char phylist_buf[128];
	int error;
	char *cp;

	error = 0;

	argv++;

	if ((error = wl_get(wl, WLC_GET_PHYLIST, phylist_buf, sizeof(phylist_buf))) < 0)
		return (error);

	cp = phylist_buf;

	for (; *cp; cp++)
		printf("%c ", *cp);
	printf("\n");

	return (0);
}

#ifdef linux
#define UPGRADE_BUFSIZE	512 /* upgrade buffer size */
#else
#define UPGRADE_BUFSIZE	1024 /* upgrade buffer size */
#endif /* linux */

static int
wl_upgrade(void *wl, cmd_t *cmd, char **argv)
{
#if	defined(_CFE_)
	return CFE_ERR_UNSUPPORTED;
#else
	FILE *fp;
	int ret = 0;
	struct {
		uint32 offset;
		char buf[UPGRADE_BUFSIZE];
	} block;
	uint len;

	if (!*++argv)
		return -1;

	if (!(fp = fopen(*argv, "rb"))) {
		fprintf(stderr, "%s: No such file or directory\n", *argv);
		return -2;
	}

	printf("Programming %s...", *argv);
	fflush(stdout);
	block.offset = 0;
	while ((len = fread(block.buf, 1, sizeof(block.buf), fp))) {
		if ((ret = wl_set(wl, cmd->set, &block, 4 + len)) < 0)
			break;
		block.offset += len;
		printf(".");
		fflush(stdout);
	}

	if (ferror(fp)) {
		ret = ferror(fp);
		printf("\nerror reading %s\n", *argv);
	} else {
		long status = WLC_UPGRADE_PENDING;
		int retries;

		printf("\nCommitting image to flash...\n");
		while (status == WLC_UPGRADE_PENDING) {
			retries = 10;
retry:
			if ((ret = wl_get(wl, WLC_UPGRADE_STATUS,
				&status, sizeof(status))) < 0) {
				/* the first attempt to get status will
				 * likely fail due to dev reset
				 */
				if (retries--)
					goto retry;
				break;
			}
		}
		if (status == WLC_UPGRADE_SUCCESS)
			printf("\nDone\n\nSuccessfully downloaded %d bytes\n", block.offset);
		else
			fprintf(stderr, "\n*** UPGRADE FAILED! *** (status %ld)\n", status);
	}

	fclose(fp);
	return ret;
#endif /* _CFE_ */
}

#include <bcmnvram.h>

static int
wl_otpw(void *wl, cmd_t *cmd, char **argv)
{
#if	defined(_CFE_)
	return CFE_ERR_UNSUPPORTED;
#else
	FILE *fp;
	int ret = 0;
	struct nvram_header *nvr;
	char *p, otpw_buf[1024 - 128];
	const char *msg;
	uint len;

	if (!*++argv)
		return -1;

	if (!(fp = fopen(*argv, "rb"))) {
		fprintf(stderr, "%s: No such file or directory\n", *argv);
		return -2;
	}

	len = fread(otpw_buf, 1, sizeof(otpw_buf) - 1, fp);
	if ((ret = ferror(fp))) {
		printf("\nerror %d reading %s\n", ret, *argv);
		ret = -3;
		goto out;
	}
	if (!feof(fp)) {
		printf("\nFile %s too large\n", *argv);
		ret = -4;
		goto out;
	}

	/* Got the bits, do they look like the output of nvserial? */
	nvr = (struct nvram_header *)otpw_buf;
	if (nvr->magic == NVRAM_MAGIC) {
		if (cmd->set == WLC_OTPW) {
			printf("File %s looks like an nvserial file, use nvotpw\n", *argv);
			fflush(stdout);
			ret = -5;
			goto out;
		}
		len  = nvr->len - sizeof(struct nvram_header);
		if (len & 1) {
			otpw_buf[len++] = '\0';
		}
		p = (char *)(nvr + 1);
		msg = "nvserial";
	} else {
		if (cmd->set == WLC_NVOTPW) {
			printf("File %s is not an nvserial file\n", *argv);
			ret = -6;
			goto out;
		}
		if (len & 1) {
			printf("File %s has an odd length (%d)\n", *argv, len);
			ret = -7;
			goto out;
		}
		p = otpw_buf;
		msg = "raw";
	}

	printf("Writing %d bytes from %s file %s to otp ...\n", len, msg, *argv);
	fflush(stdout);

	if ((ret = wl_set(wl, cmd->set, p, len)) < 0) {
		printf("\nError %d writing %s to otp\n", ret, *argv);
	}

out:
	fclose(fp);
	return ret;
#endif /* _CFE_ */
}

static int
wl_get_pktcnt(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	get_pktcnt_t pktcnt;

	memset(&pktcnt, 0, sizeof(pktcnt));
	if ((ret = wl_get(wl, cmd->get, &pktcnt, sizeof(pktcnt))) < 0)
		return ret;

	printf("Receive: good packet %d, bad packet %d, othercast good packet %d\n",
		pktcnt.rx_good_pkt, pktcnt.rx_bad_pkt, pktcnt.rx_ocast_good_pkt);
	printf("Transmit: good packet %d, bad packet %d\n", pktcnt.tx_good_pkt, pktcnt.tx_bad_pkt);

	return ret;
}

static int
wl_interfere(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int val;
	char *endptr;
	int mode;

	if (!*++argv) {
		if (cmd->get < 0)
			return -1;
		if ((ret = wl_get(wl, cmd->get, &mode, sizeof(mode))) < 0)
			return ret;
		switch (mode & 0x7f) {
		case INTERFERE_NONE:
			printf("All interference mitigation is disabled.\n");
			break;
		case NON_WLAN:
			printf("Non-wireless LAN Interference mitigation is enabled.\n");
			break;
		case WLAN_MANUAL:
			printf("Wireless LAN Interference mitigation is enabled.\n");
			break;
		case WLAN_AUTO:
			printf("Auto Wireless LAN Interference mitigation is enabled and ");
			if (mode & AUTO_ACTIVE)
				printf("active\n");
			else
				printf("not active\n");

			break;
		}
		return 0;
	} else {
		mode = INTERFERE_NONE;
		val = strtol(*argv, &endptr, 0);
		if (*endptr != '\0')
			return (-1);

		switch (val) {
			case 0:
				mode = INTERFERE_NONE;
				break;
			case 1:
				mode = NON_WLAN;
				break;
			case 2:
				mode = WLAN_MANUAL;
				break;
			case 3:
				mode = WLAN_AUTO;
				break;
			default:
				return (-1);
		}

		return wl_set(wl, cmd->set, &mode, sizeof(mode));
	}
}

static cntry_name_t *
wlc_cntry_name_to_country(char *long_name)
{
	cntry_name_t *cntry;
	for (cntry = cntry_names; cntry->name &&
		stricmp(long_name, cntry->name); cntry++);
	return (!cntry->name ? NULL : cntry);
}

static cntry_name_t *
wlc_cntry_abbrev_to_country(const char *abbrev)
{
	cntry_name_t *cntry;
	if (!*abbrev || strlen(abbrev) > 3 || strlen(abbrev) < 2)
		return (NULL);
	for (cntry = cntry_names; cntry->name &&
		strnicmp(abbrev, cntry->abbrev, strlen(abbrev)); cntry++);
	return (!cntry->name ? NULL : cntry);
}

int
wl_country(void *wl, cmd_t *cmd, char **argv)
{
	cntry_name_t *cntry;
	const char* name = "<unknown>";
	const char* abbrev;
	int ret;
	uint i;

	buf[0] = 0;
	if (!*++argv) {
		if ((ret = wl_get(wl, cmd->get, &buf, sizeof(buf))))
			return ret;
		if (strlen(buf) == 0) {
			printf("No country set\n");
			return 0;
		}
		if ((cntry = wlc_cntry_abbrev_to_country(buf)) != NULL) {
			name = cntry->name;
		}
		printf("%s/%s\n", buf, name);
		return 0;
	}

	if (!stricmp(*argv, "list")) {
		wl_country_list_t *cl = (wl_country_list_t *)buf;

		cl->buflen = sizeof(buf);
		cl->count = 0;

		/* band may follow */
		if (*++argv) {
			cl->band_set = TRUE;
			if (!stricmp(*argv, "a"))
				cl->band = WLC_BAND_5G;
			else if (!stricmp(*argv, "b") || !stricmp(*argv, "g"))
				cl->band = WLC_BAND_2G;
			else {
				printf("unsupported band: %s\n", *argv);
				return -1;
			}
		} else {
			cl->band_set = FALSE;
		}

		ret = wl_get(wl, WLC_GET_COUNTRY_LIST, buf, cl->buflen);
		if (ret < 0)
			return ret;

		printf("Supported countries: abbreviation and long name\n");
		for (i = 0; i < cl->count; i++) {
			abbrev = &cl->country_abbrev[i*WLC_CNTRY_BUF_SZ];
			cntry = wlc_cntry_abbrev_to_country(abbrev);
			printf("%s\t%s\n", abbrev, cntry ? cntry->name : abbrev);
		}
		return ret;
	}

	/* if matching long name, find abbrev name, otherwise assume it's abbrev name */
	if ((cntry = wlc_cntry_name_to_country(*argv)) != NULL)
		abbrev = cntry->abbrev;
	else
		abbrev = *argv;

	if (strlen(abbrev) > 3) {
		printf("Parameter \"%s\" was unrecognized as a country name, and is\n"
		       "too long for a max 3 character country abbreviation.\n",
		       abbrev);
		return 1;
	}

	printf("Setting country code using abbreviation: \"%s\"\n", abbrev);
	strcpy(buf, abbrev);

	if (wl_set(wl, cmd->set, buf, strlen(buf) + 1) < 0) {
		printf("Setting country \"%s\" failed !\n", abbrev);
		return 1;
	}
	return (0);
}

#define ACI_SPIN	"spin"
#define ACI_ENTER	"enter"
#define ACI_EXIT	"exit"
#define ACI_GLITCH	"glitch"


static int
wl_ampdu_tid(void *wl, cmd_t *cmd, char **argv)
{
	char *param;
	const char *cmdname = "ampdu_tid";
	struct ampdu_tid_control atc, *reply;
	uint8 tid;
	int err;
	void *ptr = NULL;

	if ((param = *++argv) == NULL)
		return USAGE_ERROR;

	tid = atoi(param);
	if (tid > MAXPRIO)
		return USAGE_ERROR;
	atc.tid = tid;

	if ((param = *++argv)) {
		atc.enable = atoi(param);
		err = wl_var_setbuf(wl, cmdname, &atc, sizeof(atc));
	} else {
		if ((err = wl_var_getbuf(wl, cmdname, &atc, sizeof(atc), &ptr) < 0))
			return err;
		reply = (struct ampdu_tid_control *)ptr;
		printf("AMPDU for tid %d: %d\n", tid, reply->enable);
	}
	return err;
}

static int
wl_ampdu_send_addba(void *wl, cmd_t *cmd, char **argv)
{
	char *param;
	const char *cmdname = "ampdu_send_addba";
	struct ampdu_ea_tid aet;
	uint8 tid;

	if ((param = *++argv) == NULL)
		return USAGE_ERROR;

	tid = atoi(param);
	if (tid > MAXPRIO)
		return USAGE_ERROR;
	aet.tid = tid;

	argv++;
	if (!*argv) {
		printf("error: missing address\n");
		return USAGE_ERROR;
	}

	if (!wl_ether_atoe(*argv, &aet.ea)) {
		printf("error: could not parse MAC address %s\n", *argv);
		return -1;
	}

	return wl_var_setbuf(wl, cmdname, &aet, sizeof(aet));
}

static int
wl_ampdu_send_delba(void *wl, cmd_t *cmd, char **argv)
{
	char *param;
	const char *cmdname = "ampdu_send_delba";
	struct ampdu_ea_tid aet;
	uint8 tid;

	if ((param = *++argv) == NULL)
		return USAGE_ERROR;

	tid = atoi(param);
	if (tid > MAXPRIO)
		return USAGE_ERROR;
	aet.tid = tid;

	argv++;
	if (!*argv) {
		printf("error: missing address\n");
		return USAGE_ERROR;
	}

	if (!wl_ether_atoe(*argv, &aet.ea)) {
		printf("error: could not parse MAC address %s\n", *argv);
		return -1;
	}

	return wl_var_setbuf(wl, cmdname, &aet, sizeof(aet));
}

/*
 *  RADAR detection parameter control
 */
static int
wl_radar_args(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	wl_radar_args_t radar_args;
	wl_radar_args_t *rap;

	if (!*++argv) {
		/* Get */
		void *ptr = NULL;

		if ((ret = wl_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return ret;

		rap = (wl_radar_args_t *)ptr;

		printf("npulses %d ncontig %d min_pw %d max_pw %d thresh0 0x%x thresh1 0x%x\n",
			rap->npulses, rap->ncontig, rap->min_pw, rap->max_pw,
			rap->thresh0, rap->thresh1);
		printf("npulses_lp %d min_pw_lp %d max_pw_lp %d min_fm_lp %d\n",
			rap->npulses_lp, rap->min_pw_lp, rap->max_pw_lp, rap->min_fm_lp);
		printf("max_deltat_lp %d min_deltat %d\n", rap->max_deltat_lp, rap->min_deltat);
	} else {
		/* Set */
		char *endptr;

		/* Order is npulses,ncontig,min_pw,max_pw, thresh0, thresh1 */
		radar_args.npulses = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.ncontig = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.min_pw = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.max_pw = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.thresh0 = (uint16)strtol(*argv, &endptr, 0);
		if (*endptr != '\0') {	/* not all the value string was parsed by strtol */
			return -1;
		}

		if (!*++argv)
			return -1;
		radar_args.thresh1 = (uint16)strtol(*argv, &endptr, 0);
		if (*endptr != '\0') {	/* not all the value string was parsed by strtol */
			return -1;
		}

		if (!*++argv)
			return -1;
		radar_args.npulses_lp = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.min_pw_lp = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.max_pw_lp = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.min_fm_lp = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.max_deltat_lp = atoi(*argv);

		if (!*++argv)
			return -1;
		radar_args.min_deltat = atoi(*argv);

		return wl_var_setbuf(wl, cmd->name, &radar_args, sizeof(wl_radar_args_t));
	}
	return ret;
}

static int
wl_dfs_status(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	wl_dfs_status_t *dfs_status_ptr;

	const char *dfs_cacstate_str[WL_DFS_CACSTATES] = {
		"IDLE",
		"PRE-ISM Channel Availability Check(CAC)",
		"In-Service Monitoring(ISM)",
		"Channel Switching Announcement(CSA)",
		"POST-ISM Channel Availability Check",
		"PRE-ISM Ouf Of Channels(OOC)",
		"POST-ISM Out Of Channels(OOC)"
	};

	void *ptr;

	if ((ret = wl_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return ret;

	dfs_status_ptr = (wl_dfs_status_t *)ptr;

	if (dfs_status_ptr->state >= WL_DFS_CACSTATES) {
		printf("Unknown dfs state %d.\n", dfs_status_ptr->state);
		return -1;
	}

	printf("state %s time elapsed %dms radar channel cleared by dfs ",
		dfs_cacstate_str[dfs_status_ptr->state], dfs_status_ptr->duration);

	if (dfs_status_ptr->chanspec_cleared) {
		printf("channel spec %d channel %d\n", dfs_status_ptr->chanspec_cleared,
			CHSPEC_CHANNEL(dfs_status_ptr->chanspec_cleared));
	}
	else {
		printf("none\n");
	}

	return ret;
}

static int
wl_wds_wpa_role_old(void *wl, cmd_t *cmd, char **argv)
{
	uint remote[2];
	uint *sup = remote;
	if (wl_get(wl, WLC_WDS_GET_REMOTE_HWADDR, remote, sizeof(remote)) < 0) {
		printf("Unable to get remote endpoint's hwaddr\n");
		return -1;
	}
	if (wl_get(wl, cmd->get, remote, sizeof(remote)) < 0) {
		printf("Unable to get local endpoint's WPA role\n");
		return -1;
	}
	printf("Local endpoing's WPA role: %s\n", *sup ? "supplicant" : "authenticator");
	return 0;
}


static int
wl_wds_wpa_role(void *wl, cmd_t *cmd, char **argv)
{
	char var[256];
	char *mac;
	char *sup;
	int len;
	if (strlen("wds_wpa_role") + 1 + ETHER_ADDR_LEN + 1 > sizeof(var))
		return -1;
	/* build var required by WLC_GET|SET_VAR */
	len = sprintf(var, "%s", "wds_wpa_role") + 1;
	mac = var + len;
	if (wl_get(wl, WLC_WDS_GET_REMOTE_HWADDR, mac, ETHER_ADDR_LEN) < 0) {
		printf("Unable to get remote endpoint's hwaddr\n");
		return -1;
	}
	len += ETHER_ADDR_LEN + 1;
	if (argv[1]) {
		sup = mac + ETHER_ADDR_LEN;
		switch ((uchar)(*sup = atoi(argv[1]))) {
		case WL_WDS_WPA_ROLE_AUTH:
		case WL_WDS_WPA_ROLE_SUP:
		case WL_WDS_WPA_ROLE_AUTO:
			if (wl_set(wl, cmd->set, var, len) < 0)
				printf("Unable to set local endpoint's WPA role\n");
			break;
		default:
			printf("Invalid WPA role %s. %u:authenticator, %u:supplicant, %u:auto\n",
				argv[1], WL_WDS_WPA_ROLE_AUTH,
				WL_WDS_WPA_ROLE_SUP, WL_WDS_WPA_ROLE_AUTO);
			break;
		}
	}
	else if (wl_get(wl, cmd->get, var, len) < 0) {
		printf("Unable to get local endpoint's WPA role\n");
		return -1;
	}
	else {
		sup = var;
		printf("Local endpoint's WPA role: %s\n", *sup ? "supplicant" : "authenticator");
	}
	return 0;
}

static int
wl_measure_req(void *wl, cmd_t *cmd, char **argv)
{
	uint32 val;
	struct ether_addr ea;

	if (!*++argv) {
		printf("error: missing arguments\n");
		return -1;
	}

	if (!stricmp(*argv, "tpc"))
		val = WLC_MEASURE_TPC;
	else if (!stricmp(*argv, "basic"))
		val = WLC_MEASURE_CHANNEL_BASIC;
	else if (!stricmp(*argv, "cca"))
		val = WLC_MEASURE_CHANNEL_CCA;
	else if (!stricmp(*argv, "rpi"))
		val = WLC_MEASURE_CHANNEL_RPI;
	else {
		printf("error: unknown measurement type %s\n", *argv);
		return -1;
	}
	argv++;

	if (!*argv) {
		printf("error: missing target address\n");
		return -1;
	}

	if (!wl_ether_atoe(*argv, &ea)) {
		printf("error: could not parse MAC address %s\n", *argv);
		return -1;
	}

	memcpy(&buf[0], &val, sizeof(uint32));
	memcpy(&buf[4], ea.octet, ETHER_ADDR_LEN);

	return wl_set(wl, cmd->set, buf, sizeof(uint32) + ETHER_ADDR_LEN);
}

static int
wl_send_quiet(void *wl, cmd_t *cmd, char **argv)
{
	dot11_quiet_t quiet;

	if (!*++argv) {
		printf("error: missing arguments\n");
		return -1;
	}
	/* Order is count, duration, offset */
	quiet.count = atoi(*argv);
	if (!*++argv) {
		printf("error: missing arguments\n");
		return -1;
	}
	quiet.duration = atoi(*argv);
	if (!*++argv) {
		printf("error: missing arguments\n");
		return -1;
	}
	quiet.offset = atoi(*argv);
	quiet.period = 0;

	return (wl_set(wl, cmd->set, &quiet, sizeof(quiet)));
}

static int
wl_send_csa(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	wl_chan_switch_t csa_arg;

	if (!*++argv) {
		printf("error: missing arguments\n");
		return -1;
	}
	/* Order is mode, count channel */
	csa_arg.mode = atoi(*argv) ? 1 : 0;
	if (!*++argv) {
		printf("error: missing mode\n");
		return -1;
	}
	csa_arg.count = atoi(*argv);
	if (!*++argv) {
		printf("error: missing count\n");
		return -1;
	}

	if ((csa_arg.chspec = wf_chspec_aton(*argv))) {
		err = wl_var_setbuf(wl, cmd->name, &csa_arg, sizeof(csa_arg));
	} else {
		printf("Error: bad parameters \"%s\"\n", *argv);
		return -1;
	}

	return err;
}

static int
wl_var_setint(void *wl, cmd_t *cmd, char **argv)
{
	int32 val;
	char *varname;
	char *endptr;

	if (!*argv) {
		printf("set: missing arguments\n");
		return -1;
	}

	varname = *argv++;

	if (!*argv) {
		printf("set: missing value argument for set of \"%s\"\n", varname);
		return -1;
	}

	val = strtol(*argv, &endptr, 0);
	if (*endptr != '\0') {
		/* not all the value string was parsed by strtol */
		printf("set: error parsing value \"%s\" as an integer for set of \"%s\"\n",
			*argv, varname);
		return -1;
	}

	return wl_iovar_setint(wl, varname, val);
}

static int
wl_var_get(void *wl, cmd_t *cmd, char **argv)
{
	char *varname;
	char *p;

	if (!*argv) {
		printf("get: missing arguments\n");
		return -1;
	}

	varname = *argv++;

	if (*argv) {
		printf("get: error, extra arg \"%s\"\n", *argv);
		return -1;
	}

	strcpy(buf, varname);
	p = buf;
	while (*p != '\0') {
		*p = tolower((int)*p);
		p++;
	}
	return (wl_get(wl, WLC_GET_VAR, &buf, WLC_IOCTL_MAXLEN));
}

static int
wl_var_getint(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	int32 val;

	if ((err = wl_var_get(wl, cmd, argv)))
		return (err);

	val = *(int32*)buf;

	if (val < 10)
		printf("%d\n", val);
	else
		printf("%d (0x%x)\n", val, val);

	return (0);
}

static int
wl_var_getandprintstr(void *wl, cmd_t *cmd, char **argv)
{
	int err;

	if ((err = wl_var_get(wl, cmd, argv)))
		return (err);

	printf("%s\n", buf);
	return (0);
}

/* Variation: Like getandprint, but allow an int arg to be passed */
static int
wl_var_setintandprintstr(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	int32 val;
	char *varname;
	char *endptr;

	if (!*argv) {
		printf("set: missing arguments\n");
		return -1;
	}

	varname = *argv++;

	if (!*argv) {
		val = 0;
	} else {
		val = strtol(*argv, &endptr, 0);
		if (*endptr != '\0') {
			/* not all the value string was parsed by strtol */
			printf("set: error parsing value \"%s\" as an integer for set of \"%s\"\n",
			       *argv, varname);
			return -1;
		}
	}

	err = wl_iovar_getbuf(wl, varname, &val, sizeof(int), buf, WLC_IOCTL_MAXLEN);

	if (err)
		return (err);

	printf("%s\n", buf);
	return (0);
}

void
wl_printlasterror(void *wl)
{
	char error_str[128];

	if (wl_iovar_get(wl, "bcmerrorstr", error_str, sizeof(error_str)) != 0) {
		fprintf(stderr, "%s: \nError getting the last error\n", av0);
	} else {
		fprintf(stderr, "%s: %s\n", av0, error_str);
	}
}

/* just issue a wl_var_setint() or a wl_var_getint() if there is a 2nd arg */
int
wl_varint(void *wl, cmd_t *cmd, char *argv[])
{
	if (argv[1])
		return (wl_var_setint(wl, cmd, argv));
	else
		return (wl_var_getint(wl, cmd, argv));
}

static int
wl_var_getbuf(void *wl, const char *iovar, void *param, int param_len, void **bufptr)
{
	int len;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, iovar);

	/* include the null */
	len = strlen(iovar) + 1;

	if (param_len)
		memcpy(&buf[len], param, param_len);

	*bufptr = buf;

	return wl_get(wl, WLC_GET_VAR, &buf, WLC_IOCTL_MAXLEN);
}

static int
wl_var_setbuf(void *wl, const char *iovar, void *param, int param_len)
{
	int len;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, iovar);

	/* include the null */
	len = strlen(iovar) + 1;

	if (param_len)
		memcpy(&buf[len], param, param_len);

	len += param_len;

	return wl_set(wl, WLC_SET_VAR, &buf, len);
}

static int
wl_var_void(void *wl, cmd_t *cmd, char **argv)
{
	if (cmd->set < 0)
		return -1;

	return wl_var_setbuf(wl, cmd->name, NULL, 0);
}

/*
 * format an iovar buffer
 * iovar name is converted to lower case
 */
static uint
wl_iovar_mkbuf(const char *name, char *data, uint datalen, char *iovar_buf, uint buflen, int *perr)
{
	uint iovar_len;
	char *p;

	iovar_len = strlen(name) + 1;

	/* check for overflow */
	if ((iovar_len + datalen) > buflen) {
		*perr = BCME_BUFTOOSHORT;
		return 0;
	}

	/* copy data to the buffer past the end of the iovar name string */
	if (datalen > 0)
		memmove(&iovar_buf[iovar_len], data, datalen);

	/* copy the name to the beginning of the buffer */
	strcpy(iovar_buf, name);

	/* wl command line automatically converts iovar names to lower case for
	 * ease of use
	 */
	p = iovar_buf;
	while (*p != '\0') {
		*p = tolower((int)*p);
		p++;
	}

	*perr = 0;
	return (iovar_len + datalen);
}


/*
 * get named iovar providing both parameter and i/o buffers
 * iovar name is converted to lower case
 */
static int
wl_iovar_getbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	iolen = wl_iovar_mkbuf(iovar, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wl_get(wl, WLC_GET_VAR, bufptr, buflen);
}

/*
 * set named iovar providing both parameter and i/o buffers
 * iovar name is converted to lower case
 */
static int
wl_iovar_setbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	iolen = wl_iovar_mkbuf(iovar, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wl_set(wl, WLC_SET_VAR, bufptr, iolen);
}

/*
 * get named iovar without parameters into a given buffer
 * iovar name is converted to lower case
 */
static int
wl_iovar_get(void *wl, const char *iovar, void *outbuf, int len)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int err;

	/* use the return buffer if it is bigger than what we have on the stack */
	if (len > (int)sizeof(smbuf)) {
		err = wl_iovar_getbuf(wl, iovar, NULL, 0, outbuf, len);
	} else {
		memset(smbuf, 0, sizeof(smbuf));
		err = wl_iovar_getbuf(wl, iovar, NULL, 0, smbuf, sizeof(smbuf));
		if (err == 0)
			memcpy(outbuf, smbuf, len);
	}

	return err;
}

/*
 * set named iovar given the parameter buffer
 * iovar name is converted to lower case
 */
static int
wl_iovar_set(void *wl, const char *iovar, void *param, int paramlen)
{
	char smbuf[WLC_IOCTL_SMLEN];

	memset(smbuf, 0, sizeof(smbuf));

	return wl_iovar_setbuf(wl, iovar, param, paramlen, smbuf, sizeof(smbuf));
}

/*
 * get named iovar as an integer value
 * iovar name is converted to lower case
 */
static int
wl_iovar_getint(void *wl, const char *iovar, int *pval)
{
	return wl_iovar_get(wl, iovar, pval, sizeof(int));
}

/*
 * set named iovar given an integer parameter
 * iovar name is converted to lower case
 */
static int
wl_iovar_setint(void *wl, const char *iovar, int val)
{
	return wl_iovar_set(wl, iovar, &val, sizeof(int));
}

/*
 * format a bsscfg indexed iovar buffer
 */
static int
wl_bssiovar_mkbuf(const char *iovar, int bssidx, void *param,
	int paramlen, void *bufptr, int buflen, int *perr)
{
	const char *prefix = "bsscfg:";
	int8* p;
	uint prefixlen;
	uint namelen;
	uint iolen;

	prefixlen = strlen(prefix);	/* length of bsscfg prefix */
	namelen = strlen(iovar) + 1;	/* length of iovar name + null */
	iolen = prefixlen + namelen + sizeof(int) + paramlen;

	/* check for overflow */
	if (buflen < 0 || iolen > (uint)buflen) {
		*perr = BCME_BUFTOOSHORT;
		return 0;
	}

	p = (int8*)bufptr;

	/* copy prefix, no null */
	memcpy(p, prefix, prefixlen);
	p += prefixlen;

	/* copy iovar name including null */
	memcpy(p, iovar, namelen);
	p += namelen;

	/* bss config index as first param */
	memcpy(p, &bssidx, sizeof(int32));
	p += sizeof(int32);

	/* parameter buffer follows */
	if (paramlen)
		memcpy(p, param, paramlen);

	*perr = 0;
	return iolen;
}

/*
 * set named & bss indexed driver iovar providing both parameter and i/o buffers
 */
static int
wl_bssiovar_setbuf(void* wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	iolen = wl_bssiovar_mkbuf(iovar, bssidx, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wl_set(wl, WLC_SET_VAR, bufptr, iolen);
}

/*
 * get named & bss indexed driver iovar providing both parameter and i/o buffers
 */
static int
wl_bssiovar_getbuf(void* wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	iolen = wl_bssiovar_mkbuf(iovar, bssidx, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wl_get(wl, WLC_GET_VAR, bufptr, buflen);
}

/*
 * get named & bss indexed driver variable to buffer value
 */
static int
wl_bssiovar_get(void *wl, const char *iovar, int bssidx, void *outbuf, int len)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int err;

	/* use the return buffer if it is bigger than what we have on the stack */
	if (len > (int)sizeof(smbuf)) {
		err = wl_bssiovar_getbuf(wl, iovar, bssidx, NULL, 0, outbuf, len);
	} else {
		memset(smbuf, 0, sizeof(smbuf));
		err = wl_bssiovar_getbuf(wl, iovar, bssidx, NULL, 0, smbuf, sizeof(smbuf));
		if (err == 0)
			memcpy(outbuf, smbuf, len);
	}

	return err;
}

/*
 * set named & bss indexed driver variable to buffer value
 */
static int
wl_bssiovar_set(void *wl, const char *iovar, int bssidx, void *param, int paramlen)
{
	char smbuf[WLC_IOCTL_SMLEN];

	memset(smbuf, 0, sizeof(smbuf));

	return wl_bssiovar_setbuf(wl, iovar, bssidx, param, paramlen, smbuf, sizeof(smbuf));
}

/*
 * get named & bsscfg indexed driver variable as an int value
 */
static int
wl_bssiovar_getint(void *wl, const char *iovar, int bssidx, int *pval)
{
	return wl_bssiovar_get(wl, iovar, bssidx, pval, sizeof(int));
}

/*
 * set named & bsscfg indexed driver variable to int value
 */
static int
wl_bssiovar_setint(void *wl, const char *iovar, int bssidx, int val)
{
	return wl_bssiovar_set(wl, iovar, bssidx, &val, sizeof(int));
}

static int
wl_nvdump(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	void *p = NULL;
	char *q = NULL;
	const char *iovar = "nvram_dump";

	/* skip the "nvdump/nvram_dump" command name */
	argv++;

	if (*argv) {
		printf("nvdump error: extra arg \"%s\"\n", *argv);
		return -1;
	}

	if ((err = wl_var_getbuf(wl, iovar, NULL, 0, &p)) < 0) {
		if ((err = wl_get(wl, WLC_NVRAM_DUMP, &buf, WLC_IOCTL_MAXLEN)))
		    return err;
		p = buf;
	}

	q = p;
	while (*q != '\0') {
		printf("%s\n", q);
		q += strlen(q) + 1;
	}

	return err;
}

static int
wl_nvget(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	char *varname;
	const char *iovar = "nvram_get";
	void *p;

	/* skip the "nvget/nvram_get" command name */
	argv++;

	if (!*argv) {
		printf("nvget: missing arguments\n");
		return -1;
	}

	varname = *argv++;

	if (*argv) {
		printf("nvget error: extra arg \"%s\"\n", *argv);
		return -1;
	}

	if ((err = wl_var_getbuf(wl, iovar, varname, strlen(varname) + 1, &p)) < 0) {

		strcpy(buf, varname);
		if ((err = wl_get(wl, WLC_NVRAM_GET, &buf, WLC_IOCTL_MAXLEN)))
		    return err;
	}

	printf("%s\n", buf);

	return err;
}

static int
wl_nvset(void *wl, cmd_t *cmd, char **argv)
{
	char *varname;

	/* skip the "nvset" command name if present */
	if (!strcmp("nvset", *argv))
		argv++;

	if (!*argv) {
		printf("nvset: missing arguments\n");
		return -1;
	}

	varname = *argv++;

	if (*argv) {
		fprintf(stderr,
		"nvset error: extra arg \"%s\"; format is name=value (no spaces around '=')\n",
			*argv);
		return -1;
	}

	if (!strchr(varname, '=')) {
		fprintf(stderr,
		"nvset error: no '=' in \"%s\", format is name=value (no spaces around '=')\n",
			*argv);
		return -1;
	}

	strcpy(buf, varname);

	return (wl_set(wl, WLC_NVRAM_SET, &buf, strlen(buf) + 1));
}

static int
wl_chan_info(void *wl, cmd_t *cmd, char **argv)
{
	uint bitmap;
	uint channel;
	int buflen, err, first, last, minutes;
	char *param;
	bool all;

	if (!*++argv) {
		first = 0;
		last = 255;
		all = TRUE;
	} else {
		last = first = atoi(*argv);
		if (last <= 0) {
			printf(" Usage: %s [channel | All ]\n", cmd->name);
			return -1;
		}
		all = FALSE;
	}

	for (; first <= last; first++) {
		channel = first & WL_CHANSPEC_CHAN_MASK;
		if (channel < 14)
			channel |= WL_CHANSPEC_BAND_2G;
		else
			channel |= WL_CHANSPEC_BAND_5G;

		strcpy(buf, "per_chan_info");
		buflen = strlen(buf) + 1;
		param = (char *)(buf + buflen);
		memcpy(param, (char*)&channel, sizeof(channel));

		if ((err = wl_get(wl, cmd->get, buf, sizeof(buf))))
			return err;

		bitmap = *(uint *)buf;
		minutes = (bitmap >> 24) & 0xff;

		if (!(bitmap & WL_CHAN_VALID_HW)) {
			if (!all)
				printf("Invalid Channel\n");
			continue;
		}

		if (!(bitmap & WL_CHAN_VALID_SW)) {
			if (!all)
				printf("Not supported in current locale\n");
			continue;
		}

		printf("Channel %d\t", channel & WL_CHANSPEC_CHAN_MASK);

		if (bitmap & WL_CHAN_BAND_5G)
			printf("A Band");
		else
			printf("B Band");

		if (bitmap & WL_CHAN_RADAR) {
			printf(", RADAR Sensitive");
		}
		if (bitmap & WL_CHAN_RESTRICTED) {
			printf(", Restricted");
		}
		if (bitmap & WL_CHAN_PASSIVE) {
			printf(", Passive");
		}
		if (bitmap & WL_CHAN_INACTIVE) {
			printf(", Temporarily Out of Service for %d minutes", minutes);
		}
		printf("\n");
	}

	return (0);
}

static int
wl_test_tssi(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int val;
	char* endptr;

	/* toss the command name */
	argv++;

	if (!*argv)
		return -1;

	val = strtol(*argv, &endptr, 0);
	if (*endptr != '\0') {
		/* not all the value string was parsed by strtol */
		printf("set: error parsing value \"%s\" as an integer\n", *argv);
		return -1;
	}

	ret = wl_iovar_getbuf(wl, cmd->name, &val, sizeof(val),
	                      buf, WLC_IOCTL_MAXLEN);

	if (ret)
		return ret;

	val = *(int*)buf;

	wl_printint(val);

	return ret;
}

static int
wl_test_tssi_offs(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	int val;
	char* endptr;

	/* toss the command name */
	argv++;

	if (!*argv)
		return -1;

	val = strtol(*argv, &endptr, 0);
	if (*endptr != '\0') {
		/* not all the value string was parsed by strtol */
		printf("set: error parsing value \"%s\" as an integer\n", *argv);
		return -1;
	}

	ret = wl_iovar_getbuf(wl, cmd->name, &val, sizeof(val),
	                      buf, WLC_IOCTL_MAXLEN);

	if (ret)
		return ret;

	val = *(int*)buf;

	wl_printint(val);

	return ret;
}

static int
wl_sta_info(void *wl, cmd_t *cmd, char **argv)
{
	sta_info_t *sta;
	struct ether_addr ea;
	char *param;
	int buflen, err;

	/* convert the ea string into an ea struct */
	if (!*++argv || !wl_ether_atoe(*argv, &ea)) {
		printf(" ERROR: no valid ether addr provided\n");
		return -1;
	}

	strcpy(buf, "sta_info");
	buflen = strlen(buf) + 1;
	param = (char *)(buf + buflen);
	memcpy(param, (char*)&ea, ETHER_ADDR_LEN);

	if ((err = wl_get(wl, cmd->get, buf, sizeof(buf))))
		return err;

	/* display the sta info */
	sta = (sta_info_t *)buf;
	printf(" STA %s:\n", *argv);
	printf("\t rateset ");
	dump_rateset(sta->rateset.rates, sta->rateset.count);
	printf("\n\t idle %d seconds\n", sta->idle);
	printf("\t in network %d seconds\n", sta->in);
	printf("\t state:%s%s%s\n",
	       (sta->flags & WL_STA_AUTHE) ? " AUTHENTICATED" : "",
	       (sta->flags & WL_STA_ASSOC) ? " ASSOCIATED" : "",
	       (sta->flags & WL_STA_AUTHO) ? " AUTHORIZED" : "");
	printf("\t flags 0x%x:%s%s%s%s%s%s%s%s%s\n", sta->flags,
	       (sta->flags & WL_STA_BRCM) ? " BRCM" : "",
	       (sta->flags & WL_STA_ABCAP) ? " ABCAP" : "",
	       (sta->flags & WL_STA_WME) ? " WME" : "",
	       (sta->flags & WL_STA_PS) ? " PS" : "",
	       (sta->flags & WL_STA_APSD_BE) ? " APSD_BE" : "",
	       (sta->flags & WL_STA_APSD_BK) ? " APSD_BK" : "",
	       (sta->flags & WL_STA_APSD_VI) ? " APSD_VI" : "",
	       (sta->flags & WL_STA_APSD_VO) ? " APSD_VO" : "",
	       (sta->flags & WL_STA_N_CAP) ? " N_CAP" : "");

	return (0);
}

static int
wl_revinfo(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	wlc_rev_info_t revinfo;

	err = wl_get(wl, WLC_GET_REVINFO, &revinfo, sizeof(revinfo));
	if (err) {
		return err;
	}

	printf("vendorid 0x%x\n", revinfo.vendorid);
	printf("deviceid 0x%x\n", revinfo.deviceid);
	printf("radiorev 0x%x\n", revinfo.radiorev);
	printf("chipnum 0x%x\n", revinfo.chipnum);
	printf("chiprev 0x%x\n", revinfo.chiprev);
	printf("corerev 0x%x\n", revinfo.corerev);
	printf("boardid 0x%x\n", revinfo.boardid);
	printf("boardvendor 0x%x\n", revinfo.boardvendor);
	printf("boardrev 0x%x\n", revinfo.boardrev);
	printf("driverrev 0x%x\n", revinfo.driverrev);
	printf("ucoderev 0x%x\n", revinfo.ucoderev);
	printf("bus 0x%x\n", revinfo.bus);

	return 0;
}

static int
wl_rm_request(void *wl, cmd_t *cmd, char **argv)
{
	miniopt_t to;
	const char* fn_name = "wl_rm_request";
	wl_rm_req_t *rm_ptr;
	wl_rm_req_t rm;
	wl_rm_req_elt_t req;
	int buflen = 0;
	int err, opt_err;
	int type;
	bool in_measure = FALSE;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	memset(&rm, 0, WL_RM_REQ_FIXED_LEN);
	memset(&req, 0, sizeof(wl_rm_req_elt_t));

	strcpy(buf, "rm_req");
	buflen = strlen(buf) + 1;

	rm_ptr = (wl_rm_req_t*)(buf + buflen);
	buflen += WL_RM_REQ_FIXED_LEN;

	/* toss the command name */
	argv++;

	miniopt_init(&to, fn_name, "p");
	while ((opt_err = miniopt(&to, argv)) != -1) {
		if (opt_err == 1) {
			err = -1;
			goto exit;
		}
		argv += to.consumed;

		if (to.opt == 't') {
			if (!to.good_int) {
				fprintf(stderr,
					"%s: could not parse \"%s\" as an int for the token\n",
					fn_name, to.valstr);
				err = -1;
				goto exit;
			}

			if (!in_measure)
				rm.token = to.val;
			else
				req.token = to.val;
		}
		if (to.opt == 'c') {
			if (!to.good_int) {
				fprintf(stderr,
					"%s: could not parse \"%s\" as an int for channel\n",
					fn_name, to.valstr);
				err = -1;
				goto exit;
			}

			req.chanspec = to.val & WL_CHANSPEC_CHAN_MASK;
			req.chanspec |= WL_CHANSPEC_BW_20 | WL_CHANSPEC_CTL_SB_NONE;
			req.chanspec |= ((to.val <= 14) ?  WL_CHANSPEC_BAND_2G :
				WL_CHANSPEC_BAND_5G);
		}
		if (to.opt == 'd') {
			if (!to.good_int) {
				fprintf(stderr,
					"%s: could not parse \"%s\" as an int for duration\n",
					fn_name, to.valstr);
				err = -1;
				goto exit;
			}
			req.dur = to.val;
		}

		if (to.opt == 'p') {
			req.flags = WL_RM_FLAG_PARALLEL;
		}

		if (to.positional) {
			if (!strcmp(to.valstr, "basic")) {
				type = WL_RM_TYPE_BASIC;
			} else if (!strcmp(to.valstr, "cca")) {
				type = WL_RM_TYPE_CCA;
			} else if (!strcmp(to.valstr, "rpi")) {
				type = WL_RM_TYPE_RPI;
			} else {
				fprintf(stderr,
					"%s: could not parse \"%s\" as a measurement type\n",
					fn_name, to.valstr);
				err = -1;
				goto exit;
			}
			/* complete the previous measurement */
			if (in_measure) {
				memcpy(buf + buflen, &req, sizeof(wl_rm_req_elt_t));
				buflen += sizeof(wl_rm_req_elt_t);
				rm.count++;
				/* measure to measure default param update */
				req.token++;	/* each measure gets a new token */
				req.flags = 0;	/* measure flags are cleared between measures */
			}
			in_measure = TRUE;
			req.type = (int8)type;
		}
	}

	/* complete the last measurement */
	if (in_measure) {
		memcpy(buf + buflen, &req, sizeof(wl_rm_req_elt_t));
		buflen += sizeof(wl_rm_req_elt_t);
		rm.count++;
	}

	if (rm.count == 0) {
		fprintf(stderr, "%s: no measurement requests specified\n",
			fn_name);
		err = -1;
		goto exit;
	}

	memcpy(rm_ptr, &rm, WL_RM_REQ_FIXED_LEN);

	err = wl_set(wl, WLC_SET_VAR, &buf, buflen);

exit:
	return err;
}

static int
wl_rm_report(void *wl, cmd_t *cmd, char **argv)
{
	wl_rm_rep_t *rep_set;
	wl_rm_rep_elt_t rep;
	char extra[128];
	char* p;
	const char* name;
	uint8* data;
	int err, bin;
	uint32 val;
	uint16 channel;
	bool aband;
	int len;

	strcpy(buf, "rm_rep");

	err = wl_get(wl, WLC_GET_VAR, &buf, WLC_IOCTL_MAXLEN);
	if (err) {
		return err;
	}

	rep_set = (wl_rm_rep_t *)buf;

	printf("Measurement Report: token %d, length %d\n", rep_set->token, rep_set->len);

	len = rep_set->len;
	data = (uint8*)rep_set->rep;
	for (; len > 0; (len -= rep.len), (data += rep.len)) {
		if (len >= WL_RM_REP_ELT_FIXED_LEN)
			memcpy(&rep, data, WL_RM_REP_ELT_FIXED_LEN);
		else
			break;

		data += WL_RM_REP_ELT_FIXED_LEN;
		len -= WL_RM_REP_ELT_FIXED_LEN;

		if (rep.type == WL_RM_TYPE_BASIC)
			name = "Basic";
		else if (rep.type == WL_RM_TYPE_CCA)
			name = "CCA";
		else if (rep.type == WL_RM_TYPE_RPI)
			name = "RPI";
		else
			name = NULL;

		if (name)
			printf("\nReport   : %s\n", name);
		else
			printf("\nReport   : %d <unknown>\n", rep.type);

		p = extra;
		if (rep.flags & WL_RM_FLAG_PARALLEL) {
			if (p != extra) p += sprintf(p, " | ");
			p += sprintf(p, "Parallel");
		}
		if (rep.flags & WL_RM_FLAG_LATE) {
			if (p != extra) p += sprintf(p, " | ");
			p += sprintf(p, "Late");
		}
		if (rep.flags & WL_RM_FLAG_INCAPABLE) {
			if (p != extra) p += sprintf(p, " | ");
			p += sprintf(p, "Incapable");
		}
		if (rep.flags & WL_RM_FLAG_REFUSED) {
			if (p != extra) p += sprintf(p, " | ");
			p += sprintf(p, "Refused");
		}

		if (p != extra) {
			printf("flags    : 0x%02x (%s)\n", rep.flags, extra);
		} else {
			printf("flags    : 0x%02x\n", rep.flags);
		}
		printf("token    : %4d\n", rep.token);

		if (rep.flags & (WL_RM_FLAG_LATE |
			WL_RM_FLAG_INCAPABLE |
			WL_RM_FLAG_REFUSED)) {
			continue;
		}

		channel = CHSPEC_CHANNEL(rep.chanspec);
		aband = CHSPEC_IS5G(rep.chanspec);

		printf("channel  : %4d %s\n", channel,
		       aband ? "(a)":"(b)");
		printf("start tsf: 0x%x:%08x\n", rep.tsf_h, rep.tsf_l);
		printf("duration : %4d TU\n", rep.dur);

		if (len < (int)rep.len) {
			printf("Error: partial report element, %d report bytes "
			       "remain, element claims %d\n",
			       len, rep.len);
			break;
		}

		if (rep.type == WL_RM_TYPE_BASIC) {
			if (rep.len >= 4) {
				memcpy(&val, data, sizeof(uint32));
				printf("Basic bits: 0x%08x\n", val);
			}
		} else if (rep.type == WL_RM_TYPE_CCA) {
			if (rep.len >= 4) {
				memcpy(&val, data, sizeof(uint32));
				printf("Carrier Fraction: %d / 255\n", val);
			}
		} else if (rep.type == WL_RM_TYPE_RPI) {
			if (rep.len >= sizeof(wl_rm_rpi_rep_t)) {
				wl_rm_rpi_rep_t rpi_rep;
				int8 min = -128;
				int8 max;

				memcpy(&rpi_rep, data, sizeof(wl_rm_rpi_rep_t));

				for (bin = 0; bin < 8; bin++) {
					max = rpi_rep.rpi_max[bin];
					if (bin == 0)
						printf("       Power <= %3d: ",
						       max);
					else if (bin < 7)
						printf(" %3d < Power <= %3d: ",
						       min, max);
					else
						printf(" %3d < Power       : ",
						       min);
					min = max;
					printf("%3d\n", rpi_rep.rpi[bin]);
				}
			}
		}
	}

	return err;
}

static int
wl_join_pref(void *wl, cmd_t *cmd, char **argv)
{
	char* data;
	int err;
	int len;
	int remaining_bytes;
	int i;
	bcm_tlv_t *ie;

	strcpy(buf, "join_pref");

	/* set */
	if (argv[1]) {
		len = strlen(buf);
		data = argv[1];
		for (i = len + 1, len += 1 + strlen(data) / 2;
		    (i < len) && (i < (int)sizeof(buf)); i ++) {
			char hex[] = "XX";
			hex[0] = *data++;
			hex[1] = *data++;
			buf[i] = (uint8)strtoul(hex, NULL, 16);
		}
		err = wl_set(wl, WLC_SET_VAR, buf, i);
	}
	/* get */
	else if (!(err = wl_get(wl, WLC_GET_VAR, buf, WLC_IOCTL_MAXLEN))) {
		len = *(int *)buf;
		data = buf + sizeof(int);
		for (i = 0; i < len; i ++)
			printf("%02x", data[i]);
		printf("\n");
		/* pretty print the join pref elements */
		remaining_bytes = len;
		ie = (bcm_tlv_t*)data;
		if (!bcm_valid_tlv(ie, remaining_bytes))
		    ie = NULL;
		while (ie) {
			wl_join_pref_print_ie(ie);
			ie = bcm_next_tlv(ie, &remaining_bytes);
		}
	}
	return err;
}

static void
wl_join_pref_print_ie(bcm_tlv_t *ie)
{
	int i;
	uint8 band;
	uint8 count;
	int suite_len;
	uint8 *suite;
	int data_bytes;


	switch (ie->id) {
	case WL_JOIN_PREF_RSSI:
		printf("Pref RSSI\n");
		if (ie->len > 2)
			printf("\t<%d extra bytes in pref data>\n", ie->len);
		break;
	case WL_JOIN_PREF_BAND:
		printf("Pref BAND: ");
		if (ie->len < 2) {
			printf("len = %d <band pref data truncated>\n", ie->len);
			break;
		}

		band = ie->data[1];
		if (band == WLC_BAND_AUTO)
			printf("0x%x AUTO (no preference)\n", band);
		else if (band == WLC_BAND_5G)
			printf("0x%x 5 GHz\n", band);
		else if (band == WLC_BAND_2G)
			printf("0x%x 2.4 GHz\n", band);
		else if (band == WLJP_BAND_ASSOC_PREF)
			printf("0x%x Use ASSOC_PREFER value\n", band);
		else
			printf("0x%x\n", band);

		if (ie->len > 2)
			printf("\t<%d extra bytes in pref data>\n", ie->len - 1);

		break;
	case WL_JOIN_PREF_WPA:
		printf("Pref WPA: ");
		if (ie->len < 2) {
			printf("len = %d <WPA pref data truncated>\n", ie->len);
			break;
		}
		count = ie->data[1];
		printf("%d ACP Specs\n", count);

		data_bytes = ie->len - 2;
		suite_len = 4; /* WPA Suite Selector length, OUI + type */
		suite = ie->data + 2;

		for (i = 0; i < (int)count; i++) {
			if (data_bytes < 3 * suite_len)
				break;
			printf("\t");
			/* AKM Suite */
			wl_join_pref_print_akm(suite);
			printf(",");

			suite = suite + suite_len;
			/* Unicast Cipher Suite */
			printf("U:");
			wl_join_pref_print_cipher_suite(suite);
			printf(",");

			suite = suite + suite_len;
			/* Multicast Cipher Suite */
			printf("M:");
			if (!memcmp(suite, WL_WPA_ACP_MCS_ANY, suite_len))
				printf("Any");
			else
				wl_join_pref_print_cipher_suite(suite);
			printf("\n");

			suite = suite + suite_len;
			data_bytes -= 3 * suite_len;
		}

		if (i != count)
			printf("\t<expected %d more specs, %d bytes>\n",
			count - i, suite_len * (count - i));
		if (data_bytes > 0)
			printf("\t<%d extra bytes>\n", data_bytes);
		break;
	default:
		printf("Pref 0x%x: len = %d\n", ie->id, ie->len);
		for (i = 0; i < ie->len; i++)
			printf("%02x", ie->data[i]);
		printf("\n");
		break;

	}

}

static void
wl_join_pref_print_akm(uint8* suite)
{
	uint8 type = suite[3];
	const char *oui_name;

	if (!memcmp(suite, WPA_OUI, 3))
		oui_name = "WPA";
	else if (!memcmp(suite, WPA2_OUI, 3))
		oui_name = "WPA2";
	else
		oui_name = NULL;

	if (oui_name) {
		if (type == RSN_AKM_NONE)
			printf("%s-NONE", oui_name);
		else if (type == RSN_AKM_UNSPECIFIED)
			printf("%s", oui_name);
		else if (type == RSN_AKM_UNSPECIFIED)
			printf("%s-PSK", oui_name);
		else
			printf("%s/0x%x", oui_name, type);
	} else {
		printf("0x%02x%02x%02x/0x%02x", suite[0], suite[1], suite[2], suite[3]);
	}
}

static void
wl_join_pref_print_cipher_suite(uint8* suite)
{
	uint8 type = suite[3];
	const char *oui_name;

	if (!memcmp(suite, WPA_OUI, 3))
		oui_name = "WPA";
	else if (!memcmp(suite, WPA2_OUI, 3))
		oui_name = "WPA2";
	else
		oui_name = NULL;

	if (oui_name) {
		if (type == WPA_CIPHER_NONE)
			printf("%s/NONE", oui_name);
		else if (type == WPA_CIPHER_WEP_40)
			printf("%s/WEP40", oui_name);
		else if (type == WPA_CIPHER_TKIP)
			printf("%s/TKIP", oui_name);
		else if (type == WPA_CIPHER_AES_CCM)
			printf("%s/AES", oui_name);
		else if (type == WPA_CIPHER_WEP_104)
			printf("%s/WEP104", oui_name);
		else
			printf("%s/0x%x", oui_name, type);
	} else {
		printf("0x%02x%02x%02x/0x%02x", suite[0], suite[1], suite[2], suite[3]);
	}
}

static int
wl_assoc_pref(void *wl, cmd_t *cmd, char **argv)
{
	uint assoc_pref;
	int err;

	/* set */
	if (argv[1]) {
		if (!strcmp(argv[1], "auto") || !strcmp(argv[1], "0"))
			assoc_pref = WLC_BAND_AUTO;
		else if (!strcmp(argv[1], "a") || !strcmp(argv[1], "1"))
			assoc_pref = WLC_BAND_5G;
		else if (!strcmp(argv[1], "b") || !strcmp(argv[1], "g") || !strcmp(argv[1], "2"))
			assoc_pref = WLC_BAND_2G;
		else
			return -1;
		err = wl_set(wl, cmd->set, &assoc_pref, sizeof(assoc_pref));
	}
	/* get */
	else if (!(err = wl_get(wl, cmd->get, &assoc_pref, sizeof(assoc_pref)))) {
		switch (assoc_pref) {
		case WLC_BAND_AUTO:
			printf("auto\n");
			break;
		case WLC_BAND_5G:
			printf("a\n");
			break;
		case WLC_BAND_2G:
			printf("b/g\n");
			break;
		}
	}
	return err;
}

/*
 * Get or Set WME Access Class (AC) parameters
 *	wl wme_ac ap|sta [be|bk|vi|vo [ecwmax|ecwmin|txop|aifsn|acm <value>] ...]
 * Without args past ap|sta, print current values
 */
static int
wl_wme_ac_req(void *wl, cmd_t *cmd, char **argv)
{
	int err, buflen;
	edcf_acparam_t acparam_cur[AC_COUNT], acparam_new[AC_COUNT], *acp;
	char *ac_str, *param, *val;
	bool acm;
	int aci, aifsn, ecwmin, ecwmax, txop;
	char ac_names[AC_COUNT][6] = {"AC_BE", "AC_BK", "AC_VI", "AC_VO"};
	int ap_mode = 0;
	int sta_param = 0;

	argv++;

	if ((err = wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode))))
		return err;

	if ((param = *argv++) == NULL)
		return USAGE_ERROR;

	if (!strcmp(param, "ap"))
		sta_param = 0;
	else if (!strcmp(param, "sta"))
		sta_param = 1;
	else
		return USAGE_ERROR;

	if (!ap_mode && !sta_param) {
		fprintf(stderr, "Can't work with AP parameters on STA\n");
		return USAGE_ERROR;
	}

	/*
	 * On call to wl_get, buf contains the NUL-terminated
	 * string "wme_ac_sta" or "wme_ac_ap".
	 * On return, gotten data starts at beginning of buf.
	 *
	 * On call to wl_set, buf contains the NUL-terminated
	 * string "wme_ac_sta" or "wme_ac_ap", followed by the data.
	 * Only a return value is returned.
	 *
	 */
	if (sta_param)
		strcpy(buf, "wme_ac_sta");
	else
		strcpy(buf, "wme_ac_ap");

	buflen = WLC_IOCTL_MAXLEN;

	/*
	 * Get current acparams, using buf as an input buffer.
	 * Return data is array of 4 ACs of wme params.
	 */

	if ((err = wl_get(wl, cmd->get, &buf, buflen)) < 0)
		return err;

	memcpy(&acparam_cur, buf, sizeof(acparam_cur));

	if ((ac_str = *argv++) == NULL) {
		printf("AC Parameters %s\n",
		       ap_mode ? (sta_param ? "advertised for STA" : "for AP") : "for STA");

		for (aci = 0; aci < AC_COUNT; aci++) {
			acp = &acparam_cur[aci];
			if (((acp->ACI & EDCF_ACI_MASK) >> EDCF_ACI_SHIFT) != aci)
				printf("Warning: AC params out of order\n");
			acm = (acp->ACI & EDCF_ACM_MASK) ? 1 : 0;
			aifsn = acp->ACI & EDCF_AIFSN_MASK;
			ecwmin = acp->ECW & EDCF_ECWMIN_MASK;
			ecwmax = (acp->ECW & EDCF_ECWMAX_MASK) >> EDCF_ECWMAX_SHIFT;
			txop = acp->TXOP;
			printf("%s: raw: ACI 0x%x ECW 0x%x TXOP 0x%x\n",
			       ac_names[aci],
			       acp->ACI, acp->ECW, acp->TXOP);
			printf("       dec: aci %d acm %d aifsn %d "
			       "ecwmin %d ecwmax %d txop 0x%x\n",
			       aci, acm, aifsn, ecwmin, ecwmax, txop);
			/* CWmin = 2^(ECWmin) - 1 */
			/* CWmax = 2^(ECWmax) - 1 */
			/* TXOP = number of 32 us units */
			printf("       eff: CWmin %d CWmax %d TXop %dusec\n",
			       EDCF_ECW2CW(ecwmin), EDCF_ECW2CW(ecwmax), EDCF_TXOP2USEC(txop));
		}

		err = 0;
	} else {
		if (strcmp(ac_str, "be") == 0)
			aci = AC_BE;
		else if (strcmp(ac_str, "bk") == 0)
			aci = AC_BK;
		else if (strcmp(ac_str, "vi") == 0)
			aci = AC_VI;
		else if (strcmp(ac_str, "vo") == 0)
			aci = AC_VO;
		else
			return USAGE_ERROR;

		/* Preload new values with current values */
		memcpy(&acparam_new, &acparam_cur, sizeof(acparam_new));

		acp = &acparam_new[aci];

		while ((param = *argv++) != NULL) {
			if ((val = *argv++) == NULL)
				return USAGE_ERROR;

			if (!strcmp(param, "acm")) {
				if (!stricmp(val, "on") || !stricmp(val, "1"))
					acp->ACI |= EDCF_ACM_MASK;
				else if (!stricmp(val, "off") || !stricmp(val, "0"))
					acp->ACI &= ~EDCF_ACM_MASK;
				else {
					fprintf(stderr, "acm value must be 1|0\n");
					return USAGE_ERROR;
				}
			} else if (!strcmp(param, "aifsn")) {
				aifsn = (int)strtol(val, NULL, 0);
				if (aifsn >= EDCF_AIFSN_MIN && aifsn <= EDCF_AIFSN_MAX)
					acp->ACI =
					        (acp->ACI & ~EDCF_AIFSN_MASK) |
					        (aifsn & EDCF_AIFSN_MASK);
				else {
					fprintf(stderr, "aifsn %d out of range (%d-%d)\n",
					        aifsn, EDCF_AIFSN_MIN, EDCF_AIFSN_MAX);
					return USAGE_ERROR;
				}
			} else if (!strcmp(param, "ecwmax")) {
				ecwmax = (int)strtol(val, NULL, 0);
				if (ecwmax >= EDCF_ECW_MIN && ecwmax <= EDCF_ECW_MAX)
					acp->ECW =
					        ((ecwmax << EDCF_ECWMAX_SHIFT) & EDCF_ECWMAX_MASK) |
					        (acp->ECW & EDCF_ECWMIN_MASK);
				else {
					fprintf(stderr, "ecwmax %d out of range (%d-%d)\n",
					        ecwmax, EDCF_ECW_MIN, EDCF_ECW_MAX);
					return USAGE_ERROR;
				}
			} else if (!strcmp(param, "ecwmin")) {
				ecwmin = (int)strtol(val, NULL, 0);
				if (ecwmin >= EDCF_ECW_MIN && ecwmin <= EDCF_ECW_MAX)
					acp->ECW =
					        ((acp->ECW & EDCF_ECWMAX_MASK) |
					         (ecwmin & EDCF_ECWMIN_MASK));
				else {
					fprintf(stderr, "ecwmin %d out of range (%d-%d)\n",
					        ecwmin, EDCF_ECW_MIN, EDCF_ECW_MAX);
					return USAGE_ERROR;
				}
			} else if (!strcmp(param, "txop")) {
				txop = (int)strtol(val, NULL, 0);
				if (txop >= EDCF_TXOP_MIN && txop <= EDCF_TXOP_MAX)
					acp->TXOP = txop;
				else {
					fprintf(stderr, "txop %d out of range (%d-%d)\n",
					        txop, EDCF_TXOP_MIN, EDCF_TXOP_MAX);
					return USAGE_ERROR;
				}
			} else {
				fprintf(stderr, "unexpected param %s\n", param);
				return USAGE_ERROR;
			}
		}

		/*
		 * Now use buf as an output buffer.
		 * Put WME acparams after "wme_ac\0" in buf.
		 * NOTE: only one of the four ACs can be set at a time.
		 */
		if (sta_param)
			strcpy(buf, "wme_ac_sta");
		else
			strcpy(buf, "wme_ac_ap");

		memcpy(buf + strlen(buf) + 1, acp, sizeof(edcf_acparam_t));

		err = wl_set(wl, cmd->set, &buf, buflen);
	}

	return err;
}

/*
 * Get or Set WME APSD control parameters
 *	wl wme_apsd_sta <max_sp_len> <be> <bk> <vi> <vo>
 *	  <max_sp_len> is 0 (all), 2, 4, or 6
 *        <be>, <bk>, <vi>, <vo> are each 0 or 1 for APSD enable
 *  with no args, print current values
 */
static int
wl_wme_apsd_sta(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	int buflen;
	char *param;
	int ap_mode;
	int qosinfo;
	int msp, max_sp_len, be, bk, vi, vo;

	if ((err = wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode))))
		return err;

	if (ap_mode) {
		printf("%s: STA only\n", cmd->name);
		return -1;
	}

	/* Display current params if no args, else set params */

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, "wme_qosinfo");
	buflen = WLC_IOCTL_MAXLEN;

	param = *++argv;

	if (param == NULL) {
		if ((err = wl_get(wl, cmd->get, &buf, buflen)) < 0)
			return err;

		memcpy(&qosinfo, buf, sizeof(qosinfo));

		msp = (qosinfo & WME_QI_STA_MAXSPLEN_MASK) >> WME_QI_STA_MAXSPLEN_SHIFT;
		be = (qosinfo & WME_QI_STA_APSD_BE_MASK) >> WME_QI_STA_APSD_BE_SHIFT;
		bk = (qosinfo & WME_QI_STA_APSD_BK_MASK) >> WME_QI_STA_APSD_BK_SHIFT;
		vi = (qosinfo & WME_QI_STA_APSD_VI_MASK) >> WME_QI_STA_APSD_VI_SHIFT;
		vo = (qosinfo & WME_QI_STA_APSD_VO_MASK) >> WME_QI_STA_APSD_VO_SHIFT;

		max_sp_len = msp * 2;

		printf("Max SP Length = %d, APSD: BE=%d BK=%d VI=%d VO=%d\n",
		       max_sp_len, be, bk, vi, vo);
	} else {
		max_sp_len = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		be = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		bk = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		vi = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		vo = (int)strtol(param, 0, 0);

		if (((be | bk | vi | vo) & ~1) | (max_sp_len & ~6)) {
			printf("%s: Invalid parameter\n", cmd->name);
			return -1;
		}

		msp = max_sp_len / 2;

		qosinfo = (msp << WME_QI_STA_MAXSPLEN_SHIFT) & WME_QI_STA_MAXSPLEN_MASK;
		qosinfo |= (be << WME_QI_STA_APSD_BE_SHIFT) & WME_QI_STA_APSD_BE_MASK;
		qosinfo |= (bk << WME_QI_STA_APSD_BK_SHIFT) & WME_QI_STA_APSD_BK_MASK;
		qosinfo |= (vi << WME_QI_STA_APSD_VI_SHIFT) & WME_QI_STA_APSD_VI_MASK;
		qosinfo |= (vo << WME_QI_STA_APSD_VO_SHIFT) & WME_QI_STA_APSD_VO_MASK;

		memcpy(&buf[strlen(buf) + 1], &qosinfo, sizeof(qosinfo));

		err = wl_set(wl, cmd->set, &buf, buflen);
	}

	return err;
}

/*
 * Get or Set WME discard policy
 *	wl wme_dp <be> <bk> <vi> <vo>
 *        <be>, <bk>, <vi>, <vo> are each 0/1 for discard newest/oldest first
 *  with no args, print current values
 */
static int
wl_wme_dp(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	int buflen;
	char *param;
	int dp;
	int be, bk, vi, vo;

	/* Display current params if no args, else set params */

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, "wme_dp");
	buflen = WLC_IOCTL_MAXLEN;

	param = *++argv;

	if (param == NULL) {
		if ((err = wl_get(wl, cmd->get, &buf, buflen)) < 0)
			return err;

		memcpy(&dp, buf, sizeof(dp));

		be = (dp >> AC_BE) & 1;
		bk = (dp >> AC_BK) & 1;
		vi = (dp >> AC_VI) & 1;
		vo = (dp >> AC_VO) & 1;

		printf("Discard oldest first: BE=%d BK=%d VI=%d VO=%d\n", be, bk, vi, vo);
	} else {
		be = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		bk = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		vi = (int)strtol(param, 0, 0);
		if ((param = *++argv) == NULL)
			return -1;
		vo = (int)strtol(param, 0, 0);

		if ((be | bk | vi | vo) & ~1) {
			printf("%s: Invalid parameter\n", cmd->name);
			return -1;
		}

		dp = (be << AC_BE) | (bk << AC_BK) | (vi << AC_VI) | (vo << AC_VO);

		memcpy(&buf[strlen(buf) + 1], &dp, sizeof(dp));

		err = wl_set(wl, cmd->set, &buf, buflen);
	}

	return err;
}

/*
 * Get or Set WME lifetime parameter
 *	"wl lifetime be|bk|vi|vo [<value>]"},
 *  with no args, print current values
 */
static int
wl_lifetime(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	uint8 ac;
	char *param, *val;
	const char *cmdname = "lifetime";
	wl_lifetime_t lifetime, *reply;
	void *ptr = NULL;

	if ((param = *++argv) == NULL)
		return USAGE_ERROR;

	if (strcmp(param, "be") == 0)
		ac = AC_BE;
	else if (strcmp(param, "bk") == 0)
		ac = AC_BK;
	else if (strcmp(param, "vi") == 0)
		ac = AC_VI;
	else if (strcmp(param, "vo") == 0)
		ac = AC_VO;
	else {
		fprintf(stderr, "unexpected param %s\n", param);
		return USAGE_ERROR;
	}

	if ((val = *++argv) == NULL) {
		lifetime.ac = ac;
		if ((err = wl_var_getbuf(wl, cmdname, &lifetime, sizeof(lifetime),
		                         &ptr)) < 0)
			return err;
		reply = (wl_lifetime_t *) ptr;
		printf("Lifetime for access class '%s' is %dms\n", param, reply->lifetime);
	}
	else {
		lifetime.ac = ac;
		lifetime.lifetime = (uint)strtol(val, 0, 0);
		err = wl_var_setbuf(wl, cmdname, &lifetime, sizeof(lifetime));
	}

	return err;
}

static int
wl_add_ie(void *wl, cmd_t *cmd, char **argv)
{
	return (wl_vndr_ie(wl, "add", argv));
}

static int
wl_del_ie(void *wl, cmd_t *cmd, char **argv)
{
	return (wl_vndr_ie(wl, "del", argv));
}

static int
wl_vndr_ie(void *wl, const char *command, char **argv)
{
	vndr_ie_setbuf_t *ie_setbuf;
	uint32 pktflag;
	int ielen, datalen, buflen, iecount;
	int err = 0;

	if (!argv[1] || !argv[2] || !argv[3]) {
		fprintf(stderr, "Too few arguments\n");
		return -1;
	}

	pktflag = (uint)strtol(argv[1], 0, 0);

	if ((pktflag &
	    ~(VNDR_IE_BEACON_FLAG |
	      VNDR_IE_PRBRSP_FLAG |
	      VNDR_IE_ASSOCRSP_FLAG |
	      VNDR_IE_AUTHRSP_FLAG |
	      VNDR_IE_PRBREQ_FLAG |
	      VNDR_IE_ASSOCREQ_FLAG))) {
		fprintf(stderr, "Invalid packet flag 0x%x (%d)\n", pktflag, pktflag);
		return -1;
	}

	ielen = atoi(argv[2]);
	if (ielen > VNDR_IE_MAX_LEN) {
		fprintf(stderr, "IE length should be <= %d\n", VNDR_IE_MAX_LEN);
		return -1;
	}
	else if (ielen < VNDR_IE_MIN_LEN) {
		fprintf(stderr, "IE length should be >= %d\n", VNDR_IE_MIN_LEN);
		return -1;
	}

	if (strlen (argv[3]) != OUI_STR_SIZE) {
		fprintf(stderr, "Invalid OUI\n");
		return -1;
	}

	datalen = ielen - VNDR_IE_MIN_LEN;

	if (datalen > 0) {
		if (!argv[4]) {
			fprintf(stderr,
			"Data bytes should be specified for IE of length %d", ielen);
			return -1;
		}
		else {
			/* Ensure each data byte is 2 characters long */
			if ((int)strlen (argv[4]) < (datalen * 2)) {
				fprintf(stderr, "Please specify all the data bytes for this IE\n");
				return -1;
			}
		}
	}

	if (!datalen && (argv[4] != NULL))
		fprintf(stderr, "Ignoring data bytes for IE of length %d", ielen);

	buflen = sizeof(vndr_ie_setbuf_t) + datalen - 1;
	ie_setbuf = (vndr_ie_setbuf_t *) malloc(buflen);

	if (!ie_setbuf) {
		fprintf(stderr, "memory alloc failure\n");
		return -1;
	}

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strcpy(ie_setbuf->cmd, command);


	/* Buffer contains only 1 IE */
	iecount = 1;
	memcpy(&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof(int));

	/*
	 * The packet flag bit field indicates the packets that will
	 * contain this IE
	 */
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag, &pktflag, sizeof(uint32));

	/* Now, add the IE to the buffer */
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len = (uchar) ielen;

	if ((err = get_oui_bytes ((uchar *)argv[3],
		&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[0]))) {
		free(ie_setbuf);
		fprintf(stderr, "Error parsing OUI arg\n");
		return err;
	}

	if (datalen) {
		if ((err = get_ie_data ((uchar *)argv[4],
			&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data[0],
			datalen))) {
			free(ie_setbuf);
			fprintf(stderr, "Error parsing data arg\n");
			return err;
		}
	}

	err = wl_var_setbuf(wl, "vndr_ie", ie_setbuf, buflen);

	free(ie_setbuf);

	return (err);
}

static int
wl_list_ie(void *wl, cmd_t *cmd, char **argv)
{
	uchar *iebuf;
	uchar *data;
	int tot_ie, pktflag, iecount, count, datalen, col;
	vndr_ie_buf_t *ie_getbuf;
	vndr_ie_info_t *ie_info;
	vndr_ie_t *ie;
	int err = 0;
	void *ptr;

	err = wl_var_getbuf(wl, "vndr_ie", NULL, 0, &ptr);
	if (err == 0) {
		ie_getbuf = (vndr_ie_buf_t *)ptr;
		memcpy(&tot_ie, &ie_getbuf->iecount, sizeof(int));
		printf("Total IEs %d\n", tot_ie);

		iebuf = (uchar *)&ie_getbuf->vndr_ie_list[0];

		for (iecount = 0; iecount < tot_ie; iecount++) {
			ie_info = (vndr_ie_info_t *) iebuf;
			memcpy(&pktflag, &ie_info->pktflag, sizeof(uint32));
			iebuf += sizeof(uint32);

			printf("\n");

			ie = &ie_info->vndr_ie_data;
			printf("IE index = %d\n", iecount);
			printf("-----------------\n");
			printf("Pkt Flg = 0x%x\n", pktflag);
			printf("Length  = %d\n", ie->len);
			printf("OUI     = %02x:%02x:%02x\n",
				ie->oui[0], ie->oui[1], ie->oui[2]);
			printf("Data:\n");

			data = &ie->data[0];
			datalen = ie->len - VNDR_IE_MIN_LEN;
			for (count = 0; (count < datalen);) {
				for (col = 0; (col < MAX_DATA_COLS) &&
					(count < datalen); col++, count++) {
					printf("%02x ", *data++);
				}
				printf("\n");
			}

			iebuf += ie->len + VNDR_IE_HDR_LEN;
		}
	}
	else {
		fprintf(stderr, "Error %d getting IOVar\n", err);
	}

	return err;
}

static int
wl_rand(void *wl, cmd_t *cmd, char **argv)
{
	char *randbuf;
	uint16 randnum;
	int err;
	void *ptr;

	if ((err = wl_var_getbuf (wl, cmd->name, NULL, 0, &ptr)))
		return (err);

	randbuf = (char *)ptr;
	memcpy(&randnum, randbuf, sizeof(uint16));
	printf("%d\n", randnum);

	return (0);
}

#define	PRVAL(name)	pbuf += sprintf(pbuf, "%s %d ", #name, cnt.name)
#define	PRNL()		pbuf += sprintf(pbuf, "\n")

static int
wl_counters(void *wl, cmd_t *cmd, char **argv)
{
	char *statsbuf;
	wl_cnt_t cnt;
	int err;
	uint i;
	char *pbuf = buf;
	void *ptr;

	if ((err = wl_var_getbuf (wl, cmd->name, NULL, 0, &ptr)))
		return (err);

	statsbuf = (char *)ptr;
	memcpy(&cnt, statsbuf, sizeof(cnt));

	if (cnt.version != WL_CNT_T_VERSION) {
		printf("\tIncorrect version of counters struct: expected %d; got %d\n",
			WL_CNT_T_VERSION, cnt.version);
		return -1;
	}

	/* summary stat counter line */
	PRVAL(txframe); PRVAL(txbyte); PRVAL(txretrans); PRVAL(txerror);
	PRVAL(rxframe); PRVAL(rxbyte); PRVAL(rxerror); PRNL();

	PRVAL(txprshort); PRVAL(txdmawar); PRVAL(txnobuf); PRVAL(txnoassoc);
	PRVAL(txchit); PRVAL(txcmiss); PRNL();

	PRVAL(reset); PRVAL(txserr); PRVAL(txphyerr); PRVAL(txphycrs);
	PRVAL(txfail); PRNL();

	pbuf += sprintf(pbuf, "d11_txfrag %d d11_txmulti %d d11_txretry %d d11_txretrie %d\n",
		cnt.txfrag, cnt.txmulti, cnt.txretry, cnt.txretrie);

	pbuf += sprintf(pbuf, "d11_txrts %d d11_txnocts %d d11_txnoack %d d11_txfrmsnt %d\n",
		cnt.txrts, cnt.txnocts, cnt.txnoack, cnt.txfrmsnt);

	PRVAL(rxcrc); PRVAL(rxnobuf); PRVAL(rxnondata); PRVAL(rxbadds);
	PRVAL(rxbadcm); PRVAL(rxdup); PRVAL(rxfragerr); PRNL();

	PRVAL(rxrunt); PRVAL(rxgiant); PRVAL(rxnoscb); PRVAL(rxbadproto);
	PRVAL(rxbadsrcmac); PRNL();

	pbuf += sprintf(pbuf, "d11_rxfrag %d d11_rxmulti %d d11_rxundec %d\n",
		cnt.rxfrag, cnt.rxmulti, cnt.rxundec);

	PRVAL(rxctl); PRVAL(rxbadda); PRVAL(rxfilter); PRNL();

	pbuf += sprintf(pbuf, "rxuflo: ");
	for (i = 0; i < NFIFO; i++)
		pbuf += sprintf(pbuf, "%d ", cnt.rxuflo[i]);
	pbuf += sprintf(pbuf, "\n");
	PRVAL(txallfrm); PRVAL(txrtsfrm); PRVAL(txctsfrm); PRVAL(txackfrm); PRNL();
	PRVAL(txdnlfrm); PRVAL(txbcnfrm); PRVAL(txtplunfl); PRVAL(txphyerr); PRNL();
	pbuf += sprintf(pbuf, "txfunfl: ");
	for (i = 0; i < NFIFO; i++)
		pbuf += sprintf(pbuf, "%d ", cnt.txfunfl[i]);
	pbuf += sprintf(pbuf, "\n");

	/* WPA2 counters */
	PRNL();
	PRVAL(tkipmicfaill); PRVAL(tkipicverr); PRVAL(tkipcntrmsr); PRNL();
	PRVAL(tkipreplay); PRVAL(ccmpfmterr); PRVAL(ccmpreplay); PRNL();
	PRVAL(ccmpundec); PRVAL(fourwayfail); PRVAL(wepundec); PRNL();
	PRVAL(wepicverr); PRVAL(decsuccess); PRVAL(rxundec); PRNL();

	PRNL();
	PRVAL(rxfrmtoolong); PRVAL(rxfrmtooshrt);
	PRVAL(rxinvmachdr); PRVAL(rxbadfcs); PRNL();
	PRVAL(rxbadplcp); PRVAL(rxcrsglitch);
	PRVAL(rxstrt); PRVAL(rxdfrmucastmbss); PRNL();
	PRVAL(rxmfrmucastmbss); PRVAL(rxcfrmucast);
	PRVAL(rxrtsucast); PRVAL(rxctsucast); PRNL();
	PRVAL(rxackucast); PRVAL(rxdfrmocast);
	PRVAL(rxmfrmocast); PRVAL(rxcfrmocast); PRNL();
	PRVAL(rxrtsocast); PRVAL(rxctsocast);
	PRVAL(rxdfrmmcast); PRVAL(rxmfrmmcast); PRNL();
	PRVAL(rxcfrmmcast); PRVAL(rxbeaconmbss);
	PRVAL(rxdfrmucastobss); PRVAL(rxbeaconobss); PRNL();
	PRVAL(rxrsptmout); PRVAL(bcntxcancl);
	PRVAL(rxf0ovfl); PRVAL(rxf1ovfl); PRNL();
	PRVAL(rxf2ovfl); PRVAL(txsfovfl); PRVAL(pmqovfl); PRNL();
	PRVAL(rxcgprqfrm); PRVAL(rxcgprsqovfl);
	PRVAL(txcgprsfail); PRVAL(txcgprssuc); PRNL();
	PRVAL(prs_timeout); PRVAL(rxnack); PRVAL(frmscons);
	PRVAL(txnack); PRVAL(txglitch_nack); PRNL();
	PRVAL(txburst); PRVAL(txphyerror); PRNL();
	PRVAL(txchanrej); PRNL();

	pbuf += sprintf(pbuf, "\n");
	fputs(buf, stdout);
	return (0);
}

static int
wl_wme_counters(void *wl, cmd_t *cmd, char **argv)
{
	char *statsbuf;
	wl_wme_cnt_t cnt;
	int err;
	void *ptr;
	char *pbuf = buf;
	char ac_names[AC_COUNT][6] = {"AC_BE", "AC_BK", "AC_VI", "AC_VO"};
	uint ac;
	int ap_mode = 0;

	if ((err = wl_var_getbuf (wl, cmd->name, NULL, 0, &ptr)))
		return (err);

	statsbuf = (char *)ptr;
	memcpy(&cnt, statsbuf, sizeof(cnt));

	if (cnt.version != WL_WME_CNT_VERSION) {
		printf("\tIncorrect version of counters struct: expected %d; got %d\n",
			WL_WME_CNT_VERSION, cnt.version);
		return -1;
	}

	if ((err = wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode)))) {
		return -1;
	}

	/* summary stat counter line */
	for (ac = AC_BE; ac < AC_COUNT; ac++) {
		pbuf += sprintf(pbuf, "\n%s: tx frames: %d bytes: %d failed frames: %d "
		                "failed bytes: %d\n",
		                ac_names[ac], cnt.tx[ac].packets, cnt.tx[ac].bytes,
		                cnt.tx_failed[ac].packets, cnt.tx_failed[ac].bytes);
		pbuf += sprintf(pbuf, "       rx frames: %d bytes: %d failed frames: %d "
		                "failed bytes: %d\n", cnt.rx[ac].packets, cnt.rx[ac].bytes,
		                cnt.rx_failed[ac].packets, cnt.rx_failed[ac].bytes);

		if (ap_mode)
			pbuf += sprintf(pbuf, "       foward frames: %d bytes: %d \n",
			                cnt.forward[ac].packets, cnt.forward[ac].bytes);

		pbuf += sprintf(pbuf, "       tx frames time expired: %d \n",
		                cnt.tx_expired[ac].packets);
	}
	pbuf += sprintf(pbuf, "\n");
	fputs(buf, stdout);
	return (0);
}

static int
wl_diag(void *wl, cmd_t *cmd, char **argv)
{
	uint testindex;
	int buflen, err;
	char *param;
	uint32 testresult;

	if (!*++argv) {
		printf(" Usage: %s testindex[1-4]\n", cmd->name);
		return -1;
	}

	testindex = atoi(*argv);

	strcpy(buf, "diag");
	buflen = strlen(buf) + 1;
	param = (char *)(buf + buflen);
	memcpy(param, (char*)&testindex, sizeof(testindex));

	if ((err = wl_get(wl, cmd->get, buf, sizeof(buf))))
		return err;

	testresult = *(uint32 *)buf;
	if (testresult != 0) {
		printf("\ndiag test %d failed(error code %d)\n", testindex, testresult);
	} else
		printf("\ndiag test %d passed\n", testindex);

	return (0);
}

void
miniopt_init(miniopt_t *t, const char* name, const char* flags)
{
	static const char *null_flags = "";

	memset(t, 0, sizeof(miniopt_t));
	t->name = name;
	if (flags == NULL)
		t->flags = null_flags;
	else
		t->flags = flags;
}

int
miniopt(miniopt_t *t, char **argv)
{
	int keylen;
	char *p, *eq, *valstr, *endptr;
	int err = 0;

	t->consumed = 0;
	t->positional = FALSE;
	memset(t->key, 0, MINIOPT_MAXKEY);
	t->opt = '\0';
	t->valstr = NULL;
	t->good_int = FALSE;

	if (*argv == NULL) {
		err = -1;
		goto exit;
	}

	p = *argv++;
	t->consumed++;

	if (!t->opt_end && !strcmp(p, "--")) {
		t->opt_end = TRUE;
		if (*argv == NULL) {
			err = -1;
			goto exit;
		}
		p = *argv++;
		t->consumed++;
	}

	if (t->opt_end) {
		t->positional = TRUE;
		valstr = p;
	}
	else if (!strncmp(p, "--", 2)) {
		eq = strchr(p, '=');
		if (eq == NULL) {
			fprintf(stderr,
				"%s: missing \" = \" in long param \"%s\"\n", t->name, p);
			err = 1;
			goto exit;
		}
		keylen = eq - (p + 2);
		if (keylen > 63) keylen = 63;
		memcpy(t->key, p + 2, keylen);

		valstr = eq + 1;
		if (*valstr == '\0') {
			fprintf(stderr,
				"%s: missing value after \" = \" in long param \"%s\"\n",
				t->name, p);
			err = 1;
			goto exit;
		}
	}
	else if (!strncmp(p, "-", 1)) {
		t->opt = p[1];
		if (strlen(p) > 2) {
			fprintf(stderr,
				"%s: only single char options, error on param \"%s\"\n",
				t->name, p);
			err = 1;
			goto exit;
		}
		if (strchr(t->flags, t->opt)) {
			/* this is a flag option, no value expected */
			valstr = NULL;
		} else {
			if (*argv == NULL) {
				fprintf(stderr,
				"%s: missing value parameter after \"%s\"\n", t->name, p);
				err = 1;
				goto exit;
			}
			valstr = *argv;
			argv++;
			t->consumed++;
		}
	} else {
		t->positional = TRUE;
		valstr = p;
	}

	/* parse valstr as int just in case */
	if (valstr) {
		t->val = (int)strtol(valstr, &endptr, 0);
		if (*endptr == '\0') {
				/* not all the value string was parsed by strtol */
			t->good_int = TRUE;
		}
	}

	t->valstr = valstr;

exit:
	if (err == 1)
		t->opt = '?';

	return err;
}

static int
get_oui_bytes(uchar *oui_str, uchar *oui)
{
	int idx;
	uchar val;
	uchar *src, *dest;
	char hexstr[3];

	src = oui_str;
	dest = oui;

	for (idx = 0; idx < MAX_OUI_SIZE; idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (uchar) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;

		if ((idx < (MAX_OUI_SIZE - 1)) && (*src++ != ':'))
			return -1;
	}

	return 0;
}

static int
get_ie_data(uchar *data_str, uchar *ie_data, int len)
{
	uchar *src, *dest;
	uchar val;
	int idx;
	char hexstr[3];

	src = data_str;
	dest = ie_data;

	for (idx = 0; idx < len; idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (uchar) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;
	}

	return 0;
}

static int
hexstrtobitvec(const char *cp, uchar *bitvec, int veclen)
{
	uchar value = 0;
	int nibble;		/* index of current hex-format nibble to process */
	int even;		/* 1 if even number of nibbles, 0 if odd number */
	int i = 0;

	if (cp[0] == '0' && cp[1] == 'x')
		cp += 2;

	memset(bitvec, '\0', veclen);
	nibble = strlen(cp);
	if (!nibble)
		return -1;
	even = ((nibble % 2) == 0);

	/* convert from right to left (lsb is rightmost byte) */
	--nibble;
	while (nibble >= 0 && i < veclen && (isxdigit((int)cp[nibble]) &&
		(value = isdigit((int)cp[nibble]) ? cp[nibble]-'0' :
		(islower((int)cp[nibble]) ? toupper((int)cp[nibble]) : cp[nibble])-'A'+10) < 16)) {
		if (even == ((nibble+1) % 2)) {
			bitvec[i] += value*16;
			++i;
		} else
			bitvec[i] = value;
		--nibble;
	}

	return ((nibble == -1 && i <= veclen) ? 0 : -1);
}

static int
wl_bitvec128(void *wl, cmd_t *cmd, char **argv)
{
	char *vbuf;
	int err;
	uchar bitvec[16];
	bool skipzeros;
	int i;

	err = 0;
	skipzeros = TRUE;

	/* set */
	if (argv[1]) {
		memset(bitvec, '\0', sizeof(bitvec));
		if (!(err = hexstrtobitvec(argv[1], bitvec, sizeof(bitvec))))
			err = wl_var_setbuf(wl, cmd->name, bitvec, sizeof(bitvec));
	}
	/* get */
	else {
		void *ptr;

		memset(buf, '\0', sizeof(buf));
		if (!(err = wl_var_getbuf(wl, cmd->name, NULL, 0, &ptr))) {
			vbuf = (char *)ptr;
			printf("0x");
			for (i = (sizeof(bitvec) - 1); i >= 0; i--) {
				if (vbuf[i] || (i == 0))
					skipzeros = FALSE;
				if (skipzeros)
					continue;
				printf("%02x", vbuf[i] & 0xff);
			}
			printf("\n");
		}
	}

	return (err);
}

static int
wl_auto_channel_sel(void *wl, cmd_t *cmd, char **argv)
{
	/*
	* The following condition(s) must be met when Auto Channel Selection
	* is enabled.
	*  - the I/F is up (change radio channel requires it is up?)
	*  - the AP must not be associated (setting SSID to empty should
	*    make sure it for us)
	*/
	int chosen = 0;
	wl_uint32_list_t request;
	int ret = 0;
#ifdef DSLCPE
	int ap_mode = 0;
	int phytype = 0;\
	int i;
	
	if ((ret = wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode)))) {
		return ret;
	}
	
	if (!ap_mode) {
		printf("This command can only be executed on the AP\n");
		return -1;
	}
	if ((ret = wl_get(wl, WLC_GET_PHYTYPE, &phytype, sizeof(phytype)))) {
		return ret;
	}	
#endif
	if (!*++argv) {
		ret = wl_get(wl, cmd->get, &chosen, sizeof(chosen));
		if (ret >= 0 && chosen != 0) {
			printf("%d\n", chosen);
			return 0;
		}
	} else {
		if (atoi(*argv) == 1) {
			request.count = 0;
			ret = wl_set(wl, cmd->set, &request, sizeof(request));
#ifdef DSLCPE
			if(!ret) {
				sleep_ms(1000);
				for(i = 0; i < 100; i++) {
					if(phytype == PHY_TYPE_N)
						ret = wl_iovar_getint(wl, "apcschspec", (int*)&chosen);
					else						
						ret = wl_get(wl, WLC_GET_CHANNEL_SEL, &chosen, sizeof(chosen));
					if(!ret)
						break;						
					sleep_ms(100);
				}				
			}		
#endif
			
		} else if (atoi(*argv) == 2) {
#ifdef DSLCPE
			if(phytype == PHY_TYPE_N) {
				ret = wl_iovar_getint(wl, "apcschspec", (int*)&chosen);
				
				if(!ret)
					ret = wl_iovar_setint(wl, "chanspec", (int)chosen);
				
				if(!ret)
					printf("chanspec 0x%4x selected \n", chosen);
				
			} else {
				ret = wl_get(wl, WLC_GET_CHANNEL_SEL, &chosen, sizeof(chosen));	
				
				if(!ret)
					ret = wl_set(wl, WLC_SET_CHANNEL, &chosen, sizeof(chosen));
					
				if(!ret)
					printf("channel %d selected \n", chosen);			
			}				
#else			
			ret = wl_get(wl, cmd->get, &chosen, sizeof(chosen));
			if (ret >= 0 && chosen != 0)
				ret = wl_set(wl, WLC_SET_CHANNEL, &chosen, sizeof(chosen));
#endif				
		} else {
			ret = -1;
		}
	}
	return ret;
}

static int
wl_varstr(void *wl, cmd_t *cmd, char **argv)
{
	int error;
	char *str;

	if (!*++argv) {
		void *ptr;

		if ((error = wl_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return (error);

		str = (char *)ptr;
		printf("%s\n", str);
		return (0);
	} else {
		str = *argv;
		/* str length include NULL */
		return wl_var_setbuf(wl, cmd->name, str, (strlen(str)+1));
	}
}

/* Return TRUE if it's one of the wc cmds. If WC_TOOL is not defined,
 * it'll return TRUE by default so all the commands are allowed.
 */
bool wc_cmd_check(const char *cmd_name)
{
	uint j;
	if (wc_cmds == NULL)
		return TRUE;

	for (j = 0; j < ARRAYSIZE(wc_cmds); j++)
		if (strcmp(wc_cmds[j], cmd_name) == 0)
			return TRUE;
	return FALSE;
}

#define NUM_TSLIST_ARG 3	/* minimum number of arguments required for TSLIST */
#define MIN_NUM_DELTS_ARG 4	/* minimum number of arguments required for DELTS */
#define MIN_NUM_ADDTS_ARG 13	/* minimum number of arguments required for ADDTS */
#define PERIODIC_TRAFFIC 1	/* Periodic traffic type */
#define VO_TID (0 << 1)		/* voice TID */
#define VI_TID (1 << 1)		/* signal TID */
#define BI_DIRECTION (3 << 5)	/* bi direction traffic stream */
#define EDCA_ACCESS (1 << 7)	/* EDCA access policy */
#define UAPSD_PSB (1 << 2)	/* U-APSD power saving behavior */
#define VO_USER_PRIO (6 << 3)	/* voice user priority */
#define VI_USER_PRIO (4 << 3)	/* signal user priority */
static int
wl_cac(void *wl, cmd_t *cmd, char **argv)
{
	int err = -1;
	int ap_mode = 0;
	int cmd_type = 0;
	tspec_arg_t tspec_arg;
	char *endptr;
	uint buflen;

	if ((wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode))))
		return err;

	if (ap_mode) {
		fprintf(stderr, "This command can only be executed on the STA\n");
		return err;
	}

	if (!strcmp(*argv, "cac_addts"))
		cmd_type = 1;
	else if (!strcmp(*argv, "cac_delts"))
		cmd_type = 2;
	else {
		fprintf(stderr, "known command\n");
		return BCME_BADARG;
	}

	/* eat command name */
	if (!*++argv)
		return BCME_BADARG;

	buflen = sizeof(tspec_arg_t);
	memset((uint8 *)&tspec_arg, 0, buflen);

	if (cmd_type == 1) {
		if (!strcmp(*argv, "G711")) {
			tspec_arg.version = TSPEC_ARG_VERSION;
			tspec_arg.length = sizeof(tspec_arg_t) - (2 * sizeof(uint16));
			tspec_arg.tsinfo.octets[0] = (PERIODIC_TRAFFIC | VO_TID |
				BI_DIRECTION | EDCA_ACCESS);
			tspec_arg.tsinfo.octets[1] = (UAPSD_PSB | VO_USER_PRIO);
			tspec_arg.tsinfo.octets[2] = 0x00;
			tspec_arg.nom_msdu_size = 0x80d0;	/* 208 bytes with msb set */
			tspec_arg.max_msdu_size = 0xd0;		/* 208 bytes */
			tspec_arg.min_srv_interval = 20000;	/* 20 msec */
			tspec_arg.max_srv_interval = 20000;
			tspec_arg.inactivity_interval = 10000000;	/* 10 sec */
			tspec_arg.suspension_interval = -1;	/* disable */
			tspec_arg.min_data_rate = 83200;	/* 83.2kbps */
			tspec_arg.mean_data_rate = 83200;
			tspec_arg.peak_data_rate = 83200;
		} else if (!strcmp(*argv, "signal")) {
			tspec_arg.version = TSPEC_ARG_VERSION;
			tspec_arg.length = sizeof(tspec_arg_t) - (2 * sizeof(uint16));
			tspec_arg.tsinfo.octets[0] = (VI_TID | BI_DIRECTION | EDCA_ACCESS);
			tspec_arg.tsinfo.octets[1] = (VI_USER_PRIO);
			tspec_arg.tsinfo.octets[2] = 0x00;
			tspec_arg.nom_msdu_size = 150;		/* 150 bytes */
			tspec_arg.max_msdu_size = 1500;		/* 1500 bytes */
			tspec_arg.suspension_interval = -1;	/* disable */
			tspec_arg.min_data_rate = 160;		/* 160 bps */
			tspec_arg.mean_data_rate = 160;
			tspec_arg.peak_data_rate = 160;
		} else {
			uint argc = 0;

			/* arg count */
			while (argv[argc])
				argc++;

			/* required argments */
			if (argc < MIN_NUM_ADDTS_ARG) {
				fprintf(stderr, "Too few arguments\n");
				fprintf(stderr, "wl cac_addts v a b c d e ...\n");
				fprintf(stderr, "\twhere ver is the structure version\n");
				fprintf(stderr, "\twhere a is byte[0] of tsinfo (bits 0-7)\n");
				fprintf(stderr, "\twhere b is byte[1] of tsinfo (bits 8-15)\n");
				fprintf(stderr, "\twhere c is byte[2] of tsinfo (bits 16-23)\n");
				fprintf(stderr, "\twhere d is the nominal MSDU size\n");
				fprintf(stderr, "\twhere e is the maximum MSDU size\n");
				fprintf(stderr, "\twhere f is the minimum service interval\n");
				fprintf(stderr, "\twhere g is the maximum service interval\n");
				fprintf(stderr, "\twhere h is the inactivity interval\n");
				fprintf(stderr, "\twhere i is the suspension interval\n");
				fprintf(stderr, "\twhere j is the minimum data rate\n");
				fprintf(stderr, "\twhere k is the mean data rate\n");
				fprintf(stderr, "\twhere l is the peak data rate\n");
				return BCME_BADARG;
			}

			tspec_arg.length = sizeof(tspec_arg_t) - (2 * sizeof(uint16));
			tspec_arg.version = (uint16)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.tsinfo.octets[0] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.tsinfo.octets[1] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.tsinfo.octets[2] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.nom_msdu_size = (uint16)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.max_msdu_size = (uint16)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.min_srv_interval = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.max_srv_interval = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.inactivity_interval = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.suspension_interval = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.min_data_rate = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.mean_data_rate = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.peak_data_rate = strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;
		}
	} else {
		if (!strcmp(*argv, "G711")) {
			tspec_arg.version = TSPEC_ARG_VERSION;
			tspec_arg.length = sizeof(tspec_arg_t) - (2 * sizeof(uint16));
			tspec_arg.tsinfo.octets[0] = (PERIODIC_TRAFFIC | VO_TID |
				BI_DIRECTION | EDCA_ACCESS);
			tspec_arg.tsinfo.octets[1] = (UAPSD_PSB | VO_USER_PRIO);
			tspec_arg.tsinfo.octets[2] = 0x00;
		} else if (!strcmp(*argv, "signal")) {
			tspec_arg.version = TSPEC_ARG_VERSION;
			tspec_arg.length = sizeof(tspec_arg_t) - (2 * sizeof(uint16));
			tspec_arg.tsinfo.octets[0] = (VI_TID | BI_DIRECTION | EDCA_ACCESS);
			tspec_arg.tsinfo.octets[1] = (VI_USER_PRIO);
			tspec_arg.tsinfo.octets[2] = 0x00;
		} else {
			uint argc = 0;

			/* arg count */
			while (argv[argc])
				argc++;

			/* required argments */
			if (argc < MIN_NUM_DELTS_ARG) {
				fprintf(stderr, "Too few arguments\n");
				fprintf(stderr, "wl cac_delts ver a b c \n");
				fprintf(stderr, "\twhere ver is the structure version\n");
				fprintf(stderr, "\twhere a is byte[0] of tsinfo (bits 0-7)\n");
				fprintf(stderr, "\twhere b is byte[1] of tsinfo (bits 8-15)\n");
				fprintf(stderr, "\twhere c is byte[2] of tsinfo (bits 16-23)\n");
				return BCME_BADARG;
			}

			tspec_arg.length = sizeof(tspec_arg_t) - (2 * sizeof(uint16));
			tspec_arg.version = (uint16)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.tsinfo.octets[0] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.tsinfo.octets[1] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;

			tspec_arg.tsinfo.octets[2] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0')
				goto error;
		}
	}

	err = wl_var_setbuf(wl, cmd->name, &tspec_arg, buflen);

error:
	return err;
}

/* get a list of traffic stream (TSINFO) in driver */
static int
wl_tslist(void *wl, cmd_t *cmd, char **argv)
{
	void *ptr;
	int i;
	int ap_mode, err = -1;
	struct tslist *tslist;

	if ((wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode))))
		return err;

	if (ap_mode) {
		fprintf(stderr, "This command can only be executed on the STA\n");
		return err;
	}

	if ((err = wl_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return err;

	tslist = (struct tslist *)ptr;
	printf("count %d\n", tslist->count);
	for (i = 0; i < tslist->count; i++)
		printf("tsinfo 0x%02X 0x%02X 0x%02X  TID %d  User Prio %d  Direction %d\n",
		       tslist->tsinfo[i].octets[0],
		       tslist->tsinfo[i].octets[1],
		       tslist->tsinfo[i].octets[2],
		       WLC_CAC_GET_TID(tslist->tsinfo[i]),
		       WLC_CAC_GET_USER_PRIO(tslist->tsinfo[i]),
		       WLC_CAC_GET_DIR(tslist->tsinfo[i]));

	return 0;
}

/* get specific TSPEC in driver */
static int
wl_tspec(void *wl, cmd_t *cmd, char **argv)
{
	void *ptr;
	int ap_mode, err = -1;
	tspec_arg_t *ts, tspec_arg;
	const char *str;
	char *temp;
	uint argc = 0;

	if ((wl_get(wl, WLC_GET_AP, &ap_mode, sizeof(ap_mode))))
		return err;

	if (ap_mode) {
		fprintf(stderr, "This command can only be executed on the STA\n");
		return err;
	}

	/* eat command name */
	argv++;

	/* arg count */
	while (argv[argc])
		argc++;

	/* required argments */
	if (argc < NUM_TSLIST_ARG) {
		fprintf(stderr, "Too few arguments\n");
		fprintf(stderr, "wl cac_tspec 0xaa 0xbb 0xcc \n");
		fprintf(stderr, "\twhere 0xaa is byte[0] of tsinfo (bits 0-7)\n");
		fprintf(stderr, "\twhere 0xbb is byte[1] of tsinfo (bits 8-15)\n");
		fprintf(stderr, "\twhere 0xcc is byte[2] of tsinfo (bits 16-23)\n");
		return BCME_BADARG;
	}

	memset((uint8 *)&tspec_arg, 0, sizeof(tspec_arg_t));

	tspec_arg.tsinfo.octets[0] = (uint8)strtol(*argv++, &temp, 0);
	if (*temp != '\0')
		goto error;

	tspec_arg.tsinfo.octets[1] = (uint8)strtol(*argv++, &temp, 0);
	if (*temp != '\0')
		goto error;

	tspec_arg.tsinfo.octets[2] = (uint8)strtol(*argv++, &temp, 0);
	if (*temp != '\0')
		goto error;

	if ((err = wl_var_getbuf(wl, cmd->name, &tspec_arg, sizeof(tspec_arg_t), &ptr)) < 0)
		return err;

	ts = (tspec_arg_t *)ptr;
	if (ts->version != TSPEC_ARG_VERSION) {
		printf("\tIncorrect version of TSPEC struct: expected %d; got %d\n",
		       TSPEC_ARG_VERSION, ts->version);
		return -1;
	}

	if (ts->length < (sizeof(tspec_arg_t) - (2 * sizeof(uint16)))) {
		printf("\tTSPEC arg length too short: expected %d; got %d\n",
		       (int)(sizeof(tspec_arg_t) - (2 * sizeof(uint16))), ts->length);
		return -1;
	}

	switch (ts->flag & TSPEC_STATUS_MASK) {
		case TSPEC_PENDING:
			str = "PENDING";
			break;
		case TSPEC_ACCEPTED:
			str = "ACCEPTED";
			break;
		case TSPEC_REJECTED:
			str = "REJECTED";
			break;
		default:
			str = "UNKNOWN";
			break;
	}

	printf("TID %d %s\n", WLC_CAC_GET_TID(ts->tsinfo), str);
	printf("tsinfo 0x%02x 0x%02x 0x%02x\n", ts->tsinfo.octets[0],
	       ts->tsinfo.octets[1], ts->tsinfo.octets[2]);
	printf("nom_msdu_size %d %s\n", (ts->nom_msdu_size & 0x7fff),
	       ((ts->nom_msdu_size & 0x8000) ? "fixed size" : ""));
	printf("max_msdu_size %d\n", ts->max_msdu_size);
	printf("min_srv_interval %d\n", ts->min_srv_interval);
	printf("max_srv_interval %d\n", ts->max_srv_interval);
	printf("inactivity_interval %d\n", ts->inactivity_interval);
	printf("suspension_interval %d\n", ts->suspension_interval);
	printf("srv_start_time %d\n", ts->srv_start_time);
	printf("min_data_rate %d\n", ts->min_data_rate);
	printf("mean_data_rate %d\n", ts->mean_data_rate);
	printf("peak_data_rate %d\n", ts->peak_data_rate);
	printf("max_burst_size %d\n", ts->max_burst_size);
	printf("delay_bound %d\n", ts->delay_bound);
	printf("min_phy_rate %d\n", ts->min_phy_rate);
	printf("surplus_bw %d\n", ts->surplus_bw);
	printf("medium_time %d\n", ts->medium_time);
	printf("\n");
	return 0;
error:
	return err;
}

static int
wl_caldump(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	void *ptr = NULL;

	if ((err = wl_var_getbuf (wl, cmd->name, NULL, 0, &ptr)) == 0) {
		printf("%s\n", (char *)ptr);
	} else {
		fprintf(stderr, "Error %d getting IOVar\n", err);
	}

	return 0;
}

static int
wl_antsel(void *wl, cmd_t *cmd, char **argv)
{
	char *val_name;
	wlc_antselcfg_t val;
	int err, argc, i;
	char *endptr;

	/* toss the command name */
	val_name = *argv++;

	if (!*argv) {
		if (cmd->get < 0)
			return -1;

		if ((err = wl_iovar_get(wl, val_name, &val, sizeof(wlc_antselcfg_t))) < 0) {
			printf("nphy antenna diversity is not supported on this device\n");
			return err;
		}


		for (i = UNICAST_TXANT_CFG; i < MAX_NUM_ANT_CFG; i++) {
			printf("0x%02x %s ",
				(val.ant_config[i] & ANTSEL_CONFIG_MASK),
				(val.ant_config[i] & WL_ANTCFG_AUTO) ? "auto" : "fixed");
		}
		printf("\n");
	} else {
		/* arg count */
		for (argc = 0; argv[argc]; argc++);

		if ((argc >= 2 && argc <= 3) || argc > MAX_NUM_ANT_CFG) {
			printf("invalid %d args\n", argc);
			return -1;
		}

		val.ant_config[UNICAST_TXANT_CFG] = (uint8)strtol(*argv++, &endptr, 0);
		if (*endptr != '\0') {
			printf("Invaild UTX parameter: %s\n", *argv);
			return -1;
		}
		printf("UTX 0x%02x\n", val.ant_config[UNICAST_TXANT_CFG]);

		if (argc == 1) {
			val.ant_config[UNICAST_RXANT_CFG] = val.ant_config[UNICAST_TXANT_CFG];
			val.ant_config[DEFAULT_TXANT_CFG] = val.ant_config[UNICAST_TXANT_CFG];
			val.ant_config[DEFAULT_RXANT_CFG] = val.ant_config[UNICAST_TXANT_CFG];
		} else {
			val.ant_config[UNICAST_RXANT_CFG] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0') {
				printf("Invaild URX parameter: %s\n", *argv);
				return -1;
			}
			val.ant_config[DEFAULT_TXANT_CFG] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0') {
				printf("Invaild DTX parameter: %s\n", *argv);
				return -1;
			}
			val.ant_config[DEFAULT_RXANT_CFG] = (uint8)strtol(*argv++, &endptr, 0);
			if (*endptr != '\0') {
				printf("Invaild DRX parameter: %s\n", *argv);
				return -1;
			}

			printf("URX 0x%02x\n", val.ant_config[UNICAST_RXANT_CFG]);
			printf("DTX 0x%02x\n", val.ant_config[DEFAULT_TXANT_CFG]);
			printf("DRX 0x%02x\n", val.ant_config[DEFAULT_RXANT_CFG]);

		}
		err = wl_iovar_set(wl, val_name, &val, sizeof(wlc_antselcfg_t));
	}
	return err;
}

static int
wl_txfifo_sz(void *wl, cmd_t *cmd, char **argv)
{
	char *param;
	const char *cmdname = "txfifo_sz";
	wlc_txfifo_sz_t ts, *reply;
	uint fifo;
	int err;
	void *ptr = NULL;

	if ((param = *++argv) == NULL)
		return USAGE_ERROR;

	fifo = atoi(param);
	if (fifo > NFIFO)
		return USAGE_ERROR;
	ts.fifo = fifo;

	if ((param = *++argv)) {
		ts.size = atoi(param);
		err = wl_var_setbuf(wl, cmdname, &ts, sizeof(ts));
	} else {
		if ((err = wl_var_getbuf(wl, cmdname, &ts, sizeof(ts), &ptr) < 0))
			return err;
		reply = (wlc_txfifo_sz_t *)ptr;
		printf("fifo %d size %d\n", fifo, reply->size);
	}
	return err;
}

#ifdef DSLCPE
static int
wl_assoclist_info(void *wl, cmd_t *cmd, char **argv)
{
	int err, i;
	void *p = NULL;
	const char *iovar = "assoclist_info";
	struct ASSOC_LIST *plistbuf;
	
	if ((err = wl_var_getbuf(wl, iovar, NULL, 0, &p)) < 0) {
		return err;
	}
	
	plistbuf=p;
	printf("Associated stations:%d\n", plistbuf->count);
	printf("Num     Mac Address        Time\n");
	for (i=0; i<plistbuf->count; i++) {
		if(*(plistbuf->client[i].mac))
			printf("%d    %s    %s\n", i+1, plistbuf->client[i].mac, plistbuf->client[i].time);
	}
	return err;	
	
}

#endif

cntry_name_t cntry_names[] = {

{"AFGHANISTAN",		"AF"},
{"ALBANIA",		"AL"},
{"ALGERIA",		"DZ"},
{"AMERICAN SAMOA",		"AS"},
{"ANDORRA",		"AD"},
{"ANGOLA",		"AO"},
{"ANGUILLA",		"AI"},
{"ANTARCTICA",		"AQ"},
{"ANTIGUA AND BARBUDA",		"AG"},
{"ARGENTINA",		"AR"},
{"ARMENIA",		"AM"},
{"ARUBA",		"AW"},
{"ASCENSION ISLAND",		"AC"},
{"ASHMORE AND CARTIER ISLANDS",		"Z1"},
{"AUSTRALIA",		"AU"},
{"AUSTRIA",		"AT"},
{"AZERBAIJAN",		"AZ"},
{"BAHAMAS",		"BS"},
{"BAHRAIN",		"BH"},
{"BAKER ISLAND",		"Z2"},
{"BANGLADESH",		"BD"},
{"BARBADOS",		"BB"},
{"BELARUS",		"BY"},
{"BELGIUM",		"BE"},
{"BELIZE",		"BZ"},
{"BENIN",		"BJ"},
{"BERMUDA",		"BM"},
{"BHUTAN",		"BT"},
{"BOLIVIA",		"BO"},
{"BOSNIA AND HERZEGOVINA",		"BA"},
{"BOTSWANA",		"BW"},
{"BOUVET ISLAND",		"BV"},
{"BRAZIL",		"BR"},
{"BRITISH INDIAN OCEAN TERRITORY",		"IO"},
{"BRUNEI DARUSSALAM",		"BN"},
{"BULGARIA",		"BG"},
{"BURKINA FASO",		"BF"},
{"BURUNDI",		"BI"},
{"CAMBODIA",		"KH"},
{"CAMEROON",		"CM"},
{"CANADA",		"CA"},
{"CAPE VERDE",		"CV"},
{"CAYMAN ISLANDS",		"KY"},
{"CENTRAL AFRICAN REPUBLIC",		"CF"},
{"CHAD",		"TD"},
{"CHANNEL ISLANDS",		"Z1"},
{"CHILE",		"CL"},
{"CHINA",		"CN"},
{"CHRISTMAS ISLAND",	"CX"},
{"CLIPPERTON ISLAND",	"CP"},
{"COCOS (KEELING) ISLANDS",		"CC"},
{"COLOMBIA",		"CO"},
{"COMOROS",		"KM"},
{"CONGO",		"CG"},
{"CONGO, THE DEMOCRATIC REPUBLIC OF THE",		"CD"},
{"COOK ISLANDS",		"CK"},
{"CORAL SEA ISLANDS",		"Z1"},
{"COSTA RICA",		"CR"},
{"COTE D'IVOIRE",		"CI"},
{"CROATIA",		"HR"},
{"CUBA",		"CU"},
{"CYPRUS",		"CY"},
{"CZECH REPUBLIC",		"CZ"},
{"DENMARK",		"DK"},
{"DIEGO GARCIA",	"Z1"},
{"DJIBOUTI",		"DJ"},
{"DOMINICA",		"DM"},
{"DOMINICAN REPUBLIC",		"DO"},
{"ECUADOR",		"EC"},
{"EGYPT",		"EG"},
{"EL SALVADOR",		"SV"},
{"EQUATORIAL GUINEA",		"GQ"},
{"ERITREA",		"ER"},
{"ESTONIA",		"EE"},
{"ETHIOPIA",		"ET"},
{"FALKLAND ISLANDS (MALVINAS)",		"FK"},
{"FAROE ISLANDS",		"FO"},
{"FIJI",		"FJ"},
{"FINLAND",		"FI"},
{"FRANCE",		"FR"},
{"FRENCH GUIANA",		"GF"},
{"FRENCH POLYNESIA",		"PF"},
{"FRENCH SOUTHERN TERRITORIES",		"TF"},
{"GABON",		"GA"},
{"GAMBIA",		"GM"},
{"GEORGIA",		"GE"},
{"GERMANY",		"DE"},
{"GHANA",		"GH"},
{"GIBRALTAR",		"GI"},
{"GREECE",		"GR"},
{"GREENLAND",		"GL"},
{"GRENADA",		"GD"},
{"GUADELOUPE",		"GP"},
{"GUAM",		"GU"},
{"GUANTANAMO BAY",		"Z1"},
{"GUATEMALA",		"GT"},
{"GUERNSEY",		"GG"},
{"GUINEA",		"GN"},
{"GUINEA-BISSAU",		"GW"},
{"GUYANA",		"GY"},
{"HAITI",		"HT"},
{"HEARD ISLAND AND MCDONALD ISLANDS",		"HM"},
{"HOLY SEE (VATICAN CITY STATE)",		"VA"},
{"HONDURAS",		"HN"},
{"HONG KONG",		"HK"},
{"HOWLAND ISLAND",		"Z2"},
{"HUNGARY",		"HU"},
{"ICELAND",		"IS"},
{"INDIA",		"IN"},
{"INDONESIA",		"ID"},
{"IRAN, ISLAMIC REPUBLIC OF",		"IR"},
{"IRAQ",		"IQ"},
{"IRELAND",		"IE"},
{"ISRAEL",		"IL"},
{"ITALY",		"IT"},
{"JAMAICA",		"JM"},
{"JAN MAYEN",		"Z1"},
{"JAPAN",		"JP"},
{"JAPAN_1",		"J1"},
{"JAPAN_2",		"J2"},
{"JAPAN_3",		"J3"},
{"JAPAN_4",		"J4"},
{"JAPAN_5",		"J5"},
{"JAPAN_6",		"J6"},
{"JAPAN_7",		"J7"},
{"JAPAN_8",		"J8"},
{"JARVIS ISLAND",		"Z2"},
{"JERSEY",		"JE"},
{"JOHNSTON ATOLL",		"Z2"},
{"JORDAN",		"JO"},
{"KAZAKHSTAN",		"KZ"},
{"KENYA",		"KE"},
{"KINGMAN REEF",		"Z2"},
{"KIRIBATI",		"KI"},
{"KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF",		"KP"},
{"KOREA, REPUBLIC OF",		"KR"},
{"KUWAIT",		"KW"},
{"KYRGYZSTAN",		"KG"},
{"LAO PEOPLE'S DEMOCRATIC REPUBLIC",		"LA"},
{"LATVIA",		"LV"},
{"LEBANON",		"LB"},
{"LESOTHO",		"LS"},
{"LIBERIA",		"LR"},
{"LIBYAN ARAB JAMAHIRIYA",		"LY"},
{"LIECHTENSTEIN",		"LI"},
{"LITHUANIA",		"LT"},
{"LUXEMBOURG",		"LU"},
{"MACAO",		"MO"},
{"MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF",		"MK"},
{"MADAGASCAR",		"MG"},
{"MALAWI",		"MW"},
{"MALAYSIA",		"MY"},
{"MALDIVES",		"MV"},
{"MALI",		"ML"},
{"MALTA",		"MT"},
{"MAN, ISLE OF",		"IM"},
{"MARSHALL ISLANDS",		"MH"},
{"MARTINIQUE",		"MQ"},
{"MAURITANIA",		"MR"},
{"MAURITIUS",		"MU"},
{"MAYOTTE",		"YT"},
{"MEXICO",		"MX"},
{"MICRONESIA, FEDERATED STATES OF",		"FM"},
{"MIDWAY ISLANDS",		"Z2"},
{"MOLDOVA, REPUBLIC OF",		"MD"},
{"MONACO",		"MC"},
{"MONGOLIA",		"MN"},
{"MONTSERRAT",		"MS"},
{"MOROCCO",		"MA"},
{"MOZAMBIQUE",		"MZ"},
{"MYANMAR",		"MM"},
{"NAMIBIA",		"NA"},
{"NAURU",		"NR"},
{"NEPAL",		"NP"},
{"NETHERLANDS",		"NL"},
{"NETHERLANDS ANTILLES",		"AN"},
{"NEW CALEDONIA",		"NC"},
{"NEW ZEALAND",		"NZ"},
{"NICARAGUA",		"NI"},
{"NIGER",		"NE"},
{"NIGERIA",		"NG"},
{"NIUE",		"NU"},
{"NORFOLK ISLAND",		"NF"},
{"NORTHERN MARIANA ISLANDS",		"MP"},
{"NORWAY",		"NO"},
{"OMAN",		"OM"},
{"PAKISTAN",		"PK"},
{"PALAU",		"PW"},
{"PALESTINIAN TERRITORY, OCCUPIED",		"PS"},
{"PALMYRA ATOLL",		"Z2"},
{"PANAMA",		"PA"},
{"PAPUA NEW GUINEA",		"PG"},
{"PARAGUAY",		"PY"},
{"PERU",		"PE"},
{"PHILIPPINES",		"PH"},
{"PITCAIRN",		"PN"},
{"POLAND",		"PL"},
{"PORTUGAL",		"PT"},
{"PUERTO RICO",		"PR"},
{"QATAR",		"QA"},
{"REUNION",		"RE"},
{"ROMANIA",		"RO"},
{"ROTA ISLAND",		"Z1"},
{"RUSSIAN FEDERATION",		"RU"},
{"RWANDA",		"RW"},
{"SAIPAN",		"Z1"},
{"SAINT HELENA",		"SH"},
{"SAINT KITTS AND NEVIS",		"KN"},
{"SAINT LUCIA",		"LC"},
{"SAINT PIERRE AND MIQUELON",		"PM"},
{"SAINT VINCENT AND THE GRENADINES",		"VC"},
{"SAMOA",		"WS"},
{"SAN MARINO",		"SM"},
{"SAO TOME AND PRINCIPE",		"ST"},
{"SAUDI ARABIA",		"SA"},
{"SENEGAL",		"SN"},
{"SEYCHELLES",		"SC"},
{"SIERRA LEONE",		"SL"},
{"SINGAPORE",		"SG"},
{"SLOVAKIA",		"SK"},
{"SLOVENIA",		"SI"},
{"SOLOMON ISLANDS",		"SB"},
{"SOMALIA",		"SO"},
{"SOUTH AFRICA",		"ZA"},
{"SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS",		"GS"},
{"SPAIN",		"ES"},
{"SRI LANKA",		"LK"},
{"SUDAN",		"SD"},
{"SURINAME",		"SR"},
{"SVALBARD AND JAN MAYEN",		"SJ"},
{"SWAZILAND",		"SZ"},
{"SWEDEN",		"SE"},
{"SWITZERLAND",		"CH"},
{"SYRIAN ARAB REPUBLIC",		"SY"},
{"TAIWAN, PROVINCE OF CHINA",		"TW"},
{"TAJIKISTAN",		"TJ"},
{"TANZANIA, UNITED REPUBLIC OF",		"TZ"},
{"THAILAND",		"TH"},
{"TIMOR-LESTE (EAST TIMOR)",		"TL"},
{"TINIAN ISLAND",	"Z1"},
{"TOGO",		"TG"},
{"TOKELAU",		"TK"},
{"TONGA",		"TO"},
{"TRINIDAD AND TOBAGO",		"TT"},
{"TRISTAN DA CUNHA",		"TA"},
{"TUNISIA",		"TN"},
{"TURKEY",		"TR"},
{"TURKMENISTAN",		"TM"},
{"TURKS AND CAICOS ISLANDS",		"TC"},
{"TUVALU",		"TV"},
{"UGANDA",		"UG"},
{"UKRAINE",		"UA"},
{"UNITED ARAB EMIRATES",		"AE"},
{"UNITED KINGDOM",		"GB"},
{"UNITED STATES",		"US"},
{"UNITED STATES MINOR OUTLYING ISLANDS",		"UM"},
{"URUGUAY",		"UY"},
{"UZBEKISTAN",		"UZ"},
{"VANUATU",		"VU"},
{"VENEZUELA",		"VE"},
{"VIET NAM",		"VN"},
{"VIRGIN ISLANDS, BRITISH",		"VG"},
{"VIRGIN ISLANDS, U.S.",		"VI"},
{"WAKE ISLAND",		"Z1"},
{"WALLIS AND FUTUNA",		"WF"},
{"WESTERN SAHARA",		"EH"},
{"YEMEN",		"YE"},
{"YUGOSLAVIA",		"YU"},
{"ZAMBIA",		"ZM"},
{"ZIMBABWE",		"ZW"},
{"RADAR CHANNELS",	"RDR"},
{"ALL CHANNELS",	"ALL"},
{NULL,			NULL}
};

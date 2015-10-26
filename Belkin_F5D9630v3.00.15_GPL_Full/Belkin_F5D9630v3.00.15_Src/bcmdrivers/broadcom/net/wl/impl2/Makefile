WLSRCBASE= $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)
WLBASE	= ./wl
SHBASE	= ./shared
COBASE	= ./bcmcrypto
obj-$(CONFIG_BCM_WLAN) += wl.o

#mark WLAN configuration
WLLX=1
WLCFGDIR	= $(WLSRCBASE)/wl/config
WLCONFFILE	= wlconfig_lx_wl_dslcpe
ifeq ($(strip $(BRCM_CHIP)),6338)
WLCONFFILE	= wlconfig_lx_wl_dslcpe_sdio 
EXTRA_CFLAGS	+= -DDSLCPE_SDIO_PIO
endif

include $(WLCFGDIR)/$(WLCONFFILE)

include $(WLCFGDIR)/wl.mk

wl_limited_objs := $(WLBASE)/sys/wl_linux_dslcpe.o
wl_limited_objs += $(SHBASE)/bcmsrom.o $(SHBASE)/linux_osl.o $(SHBASE)/bcmutils.o

wl-objs += wl_dep.o  $(wl_limited_objs)
ifneq ($(CONFIG_BCM_MIMO),)
$(obj)/wl_dep.o: $(obj)/shared/bcm4306_map.o $(obj)/shared/bcm4318_map.o $(obj)/shared/bcm4321_map.o
else
$(obj)/wl_dep.o: $(obj)/shared/bcm4306_map.o $(obj)/shared/bcm4318_map.o 
endif
	cp $(obj)/wl$(BRCM_CHIP)_partial.o_save $(obj)/wl_dep.o

include $(BRCMDRIVERS_DIR)/broadcom/net/wl/impl2/Makefile.srom

EXTRA_CFLAGS	+= -I$(WLSRCBASE)/include
EXTRA_CFLAGS 	+= -I$(INC_BRCMDRIVER_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMDRIVER_PRIV_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PRIV_PATH)/$(BRCM_BOARD) -I$(INC_BRCMBOARDPARMS_PATH)/$(BRCM_BOARD)
EXTRA_CFLAGS	+= -DIL_BIGENDIAN
EXTRA_CFLAGS	+= -DBCMDRIVER
EXTRA_CFLAGS	+= $(WLFLAGS)
EXTRA_CFLAGS	+= -DDSLCPE
EXTRA_CFLAGS	+= -DDSLCPE_DGASP
EXTRA_CFLAGS	+= -DWLTEST
#EXTRA_CFLAGS	+= -DBCMDBG
EXTRA_CFLAGS	+= -I$(WLSRCBASE)/wl/sys
EXTRA_CFLAGS	+= -DDSLCPE_WOMBO
	
-include $(TOPDIR)/Rules.make


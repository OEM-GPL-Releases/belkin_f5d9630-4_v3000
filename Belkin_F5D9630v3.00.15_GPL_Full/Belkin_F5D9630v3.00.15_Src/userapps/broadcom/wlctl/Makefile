#
# Makefile for wlctl utility.
#
PROGRAM_NAME:= wlctl

CFLAGS =-s -Os -fomit-frame-pointer -I$(INC_BRCMDRIVER_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMDRIVER_PRIV_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PRIV_PATH)/$(BRCM_BOARD)
LDFLAGS=-Os -Wl,-allow-shlib-undefined

WIRELESS_DRIVER_PATH=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)
INC_WIRELESS_DRIVER_PATH=$(WIRELESS_DRIVER_PATH)/include
SHARED_WIRELESS_DRIVER_PATH=$(WIRELESS_DRIVER_PATH)/shared

INC_KERNEL_INC_PATH=$(KERNEL_DIR)/include
CFLAGS += -Wall -I$(INC_WIRELESS_DRIVER_PATH) -I$(INC_WIRELESS_DRIVER_PATH)/proto -I$(INC_BRCMCFM_PATH) -I$(INC_KERNEL_INC_PATH) -DDSLCPE

ifeq ($(strip $(BUILD_WLCTL)), static)
CFLAGS += -DBUILD_STATIC 
endif
CFLAGS += -DBCMWPA2 -DIL_BIGENDIAN

ifeq ($(DSLCPE_DT_BUILD),1)
CFLAGS	+= -DRADIUS_RESTRICTION
endif

ifeq ($(strip $(BRCM_CHIP)),6338)
CFLAGS += -DBCMSDIO
endif

WLCTLOBJS = wlu_linux.o wlu.o
SHAREDOBJS = bcmutils.o bcmwifi.o
OBJS = $(WLCTLOBJS) $(SHAREDOBJS)

vpath %.c $(SHARED_WIRELESS_DRIVER_PATH) $(CRYPTO_WIRELESS_DRIVER_PATH)


all: $(PROGRAM_NAME)

install::
	install -m 755 $(PROGRAM_NAME) $(INSTALL_DIR)/bin
	$(STRIP) $(INSTALL_DIR)/bin/$(PROGRAM_NAME)
	mkdir -p $(INSTALL_DIR)/sbin
	ln -sf $(PROGRAM_NAME) $(INSTALL_DIR)/bin/wl

dynamic: all install

static: $(PROGRAM_NAME).a

.c.o:
	$(CC) $(CFLAGS) -c $<

$(PROGRAM_NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROGRAM_NAME) $(OBJS)

$(PROGRAM_NAME).a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

clean:
	-rm -f $(PROGRAM_NAME) *.o  $(PROGRAM_NAME).a





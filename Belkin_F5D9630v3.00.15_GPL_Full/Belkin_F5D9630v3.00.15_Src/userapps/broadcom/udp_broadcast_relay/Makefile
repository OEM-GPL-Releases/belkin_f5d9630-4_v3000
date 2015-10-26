all:
	cp udp_broadcast_relay_$(PROFILE)_save udp_broadcast_relay

install:
	install -m 755 udp_broadcast_relay $(INSTALL_DIR)/bin
	$(STRIP) $(INSTALL_DIR)/bin/udp_broadcast_relay	

dynamic: all install

clean:
	rm -f udp_broadcast_relay


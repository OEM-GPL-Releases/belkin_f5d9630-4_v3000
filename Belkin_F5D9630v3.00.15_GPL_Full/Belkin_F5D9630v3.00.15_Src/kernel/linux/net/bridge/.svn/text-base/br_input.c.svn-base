/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#if defined(CONFIG_MIPS_BRCM)
#include <linux/if_vlan.h>
#include <linux/timer.h>
#include <linux/igmp.h>
#include <linux/ip.h>
#endif
#include "br_private.h"

#if defined(CONFIG_MIPS_BRCM)
#define SNOOPING_BLOCKING_MODE 2
#endif

const unsigned char bridge_ula[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

union ip_array {
	unsigned int ip_addr;
        unsigned char ip_ar[4];
};

static int br_pass_frame_up_finish(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
#if defined(CONFIG_MIPS_BRCM)
	/* If pass up to IP, remove VLAN header */
	if (skb->protocol == __constant_htons(ETH_P_8021Q)) {
		unsigned short proto;
		struct vlan_hdr *vhdr = (struct vlan_hdr *)(skb->data);

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (skb) {
			memmove(skb->data - ETH_HLEN + VLAN_HLEN,
				skb->data - ETH_HLEN, 12);
			skb_pull(skb, VLAN_HLEN);
			skb->mac.raw += VLAN_HLEN;
			skb->nh.raw += VLAN_HLEN;
			skb->h.raw += VLAN_HLEN;
		}
		/* make sure protocol is correct before passing up */
		proto = vhdr->h_vlan_encapsulated_proto;
		skb->protocol = proto;
		/* TODO: do we need to assign skb->priority? */
	}
#endif
	netif_rx(skb);

	return 0;
}

static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	br->statistics.rx_packets++;
	br->statistics.rx_bytes += skb->len;

	indev = skb->dev;
	skb->dev = br->dev;

	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
			br_pass_frame_up_finish);
}

void query_timeout(unsigned long ptr)
{
	struct net_bridge_mc_fdb_entry *dst;
	struct list_head *tmp;
	struct list_head *lh;
	struct net_bridge *br;
    
	br = (struct net_bridge *) ptr;

	spin_lock_bh(&br->mcl_lock);
	list_for_each_safe_rcu(lh, tmp, &br->mc_list) {
	    dst = (struct net_bridge_mc_fdb_entry *) list_entry(lh, struct net_bridge_mc_fdb_entry, list);
	    if (jiffies > dst->tstamp) {
		list_del_rcu(&dst->list);
		kfree(dst);
	    }
	}
	spin_unlock_bh(&br->mcl_lock);
		
	mod_timer(&br->igmp_timer, jiffies + TIMER_CHECK_TIMEOUT*HZ);		
}

void addr_debug(unsigned char *dest)
{
#define NUM2PRINT 50
	char buf[NUM2PRINT * 3 + 1];	/* 3 chars per byte */
	int i = 0;
	for (i = 0; i < 6 && i < NUM2PRINT; i++) {
		sprintf(buf + i * 3, "%2.2x ", 0xff & dest[i]);
	}
	printk("%s ", buf);
}


#if defined(CONFIG_MIPS_BRCM)
void addr_conv(unsigned char *in, char * out)
{
    sprintf(out, "%02x%02x%02x%02x%02x%02x", in[0], in[1], in[2], in[3], in[4], in[5]);
}

mac_addr upnp_addr = {{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}};
mac_addr sys1_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}};
mac_addr sys2_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x02}};
mac_addr ospf1_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x05}};
mac_addr ospf2_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x06}};
mac_addr ripv2_addr = {{0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}};
mac_addr sys_addr = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

int control_filter(unsigned char *dest)
{
    if ((!memcmp(dest, &upnp_addr, ETH_ALEN)) ||
	(!memcmp(dest, &sys1_addr, ETH_ALEN)) ||
	(!memcmp(dest, &sys2_addr, ETH_ALEN)) ||
	(!memcmp(dest, &ospf1_addr, ETH_ALEN)) ||
	(!memcmp(dest, &ospf2_addr, ETH_ALEN)) ||
	(!memcmp(dest, &sys_addr, ETH_ALEN)) ||
	(!memcmp(dest, &ripv2_addr, ETH_ALEN)))
	    return 0;
    else
	return 1;
}

void brcm_conv_ip_to_mac(char *ipa, char *maca)
{
        maca[0] = 0x01;
        maca[1] = 0x00;
        maca[2] = 0x5e;
        maca[3] = 0x7F & ipa[1];
        maca[4] = ipa[2];
        maca[5] = ipa[3];

        return;
}

int mc_forward(struct net_bridge *br, struct sk_buff *skb, unsigned char *dest,int forward, int clone)
{
	struct net_bridge_mc_fdb_entry *dst;
	struct list_head *lh;
	int status = 0;
	struct sk_buff *skb2;
	struct net_bridge_port *p;
	unsigned char tmp[6];
	struct igmpv3_report *report;
	struct igmpv3_grec *grec;
	int i;
	struct iphdr *pip = skb->nh.iph;
	struct in_addr src;
	union ip_array igmpv3_mcast;

	if (!snooping)
		return 0;

	if ((snooping == SNOOPING_BLOCKING_MODE) && control_filter(dest))
	    status = 1;

	if (skb->data[9] == IPPROTO_IGMP) {
	    // For proxy; need to add some intelligence here 
	    if (!br->proxy) {
		if ((skb->data[24] == IGMPV2_HOST_MEMBERSHIP_REPORT) &&
		    (skb->protocol == __constant_htons(ETH_P_IP))) {
		    br_mc_fdb_add(br, skb->dev->br_port, dest, skb->mac.ethernet->h_source);
                }
                else if((skb->data[24] == IGMPV3_HOST_MEMBERSHIP_REPORT) &&
                        (skb->protocol == __constant_htons(ETH_P_IP))) {
                    report = (struct igmpv3_report *)&skb->data[24];
                    grec = &report->grec[0];
                    for(i = 0; i < report->ngrec; i++) {
                        igmpv3_mcast.ip_addr = grec->grec_mca;
                        brcm_conv_ip_to_mac(igmpv3_mcast.ip_ar, tmp);
                        br_mc_fdb_add(br, skb->dev->br_port, &tmp, skb->mac.ethernet->h_source);
                        grec = (struct igmpv3_grec *)((char *)grec + IGMPV3_GRP_REC_SIZE(grec));
                    }
                }
		else if (skb->data[24] == IGMP_HOST_LEAVE_MESSAGE) {
		    tmp[0] = 0x01;
		    tmp[1] = 0x00;
		    tmp[2] = 0x5e;
		    tmp[3] = 0x7F & skb->data[29];
		    tmp[4] = skb->data[30];
		    tmp[5] = skb->data[31];
		    br_mc_fdb_remove(br, skb->dev->br_port, tmp, skb->mac.ethernet->h_source);
		}
		else
		    ;
	    }
	    return 0;
	}

	/*
	if (clone) {
		struct sk_buff *skb3;

		if ((skb3 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
			br->statistics.tx_dropped++;
			return;
		}

		skb = skb3;
	}
	*/
	
	list_for_each_rcu(lh, &br->mc_list) {
	    dst = (struct net_bridge_mc_fdb_entry *) list_entry(lh, struct net_bridge_mc_fdb_entry, list);
	    if (!memcmp(&dst->addr, dest, ETH_ALEN)) {
		if (!dst->dst->dirty) {
		    skb2 = skb_clone(skb, GFP_ATOMIC);
		    if (forward)
			br_forward(dst->dst, skb2);
		    else
			br_deliver(dst->dst, skb2);
		}
		dst->dst->dirty = 1;
		status = 1;
	    }
	}
	if (status) {
	    list_for_each_entry_rcu(p, &br->port_list, list) {
		p->dirty = 0;
	  }
	}

	if ((!forward) && (status))
	kfree_skb(skb);

	return status;
}
#endif

int br_handle_frame_finish(struct sk_buff *skb)
{
	struct net_bridge *br;
	unsigned char *dest;
#if defined(CONFIG_MIPS_BRCM)
	unsigned char *src;
#endif
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_port *p;
	int passedup;

	dest = skb->mac.ethernet->h_dest;
#if defined(CONFIG_MIPS_BRCM)
	src = skb->mac.ethernet->h_source;
#endif
	
	rcu_read_lock();
	p = skb->dev->br_port;
	smp_read_barrier_depends();

	if (p == NULL || p->state == BR_STATE_DISABLED) {
		kfree_skb(skb);
		goto out;
	}

	br = p->br;
	passedup = 0;
	if (br->dev->flags & IFF_PROMISC) {
		struct sk_buff *skb2;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 != NULL) {
			passedup = 1;
			br_pass_frame_up(br, skb2);
		}
	}

	if (dest[0] & 1) {
#if defined(CONFIG_MIPS_BRCM)
		if (snooping && br->proxy) {
		  if (skb->data[9] == IPPROTO_IGMP) {
		    char destS[16];
		    char srcS[16];

		    if (skb->data[24] == IGMP_HOST_LEAVE_MESSAGE) {
			unsigned char tmp[6];
			
		        brcm_conv_ip_to_mac(&skb->data[29], tmp);
			addr_conv(tmp, destS);
		    }
		    else
			addr_conv(dest, destS);
		    addr_conv(src, srcS);
		    sprintf(skb->extif, "%s %s %s/%s", br->dev->name, p->dev->name, destS, srcS);
		  }
		}
		if (!mc_forward(br, skb, dest, 1, !passedup))		
#endif
		br_flood_forward(br, skb, !passedup);
		if (!passedup)
			br_pass_frame_up(br, skb);
		goto out;
	}

	dst = __br_fdb_get(br, dest);
	if (dst != NULL && dst->is_local) {
		if (!passedup)
			br_pass_frame_up(br, skb);
		else
			kfree_skb(skb);
		goto out;
	}

	if (dst != NULL) {
		br_forward(dst->dst, skb);
		goto out;
	}

	br_flood_forward(br, skb, 0);

out:
	rcu_read_unlock();
	return 0;
}

int br_handle_frame(struct sk_buff *skb)
{
	unsigned char *dest;
	struct net_bridge_port *p;

	dest = skb->mac.ethernet->h_dest;

	rcu_read_lock();
	p = skb->dev->br_port;
	if (p == NULL || p->state == BR_STATE_DISABLED)
		goto err;

	if (skb->mac.ethernet->h_source[0] & 1)
		goto err;

	if (p->state == BR_STATE_LEARNING ||
	    p->state == BR_STATE_FORWARDING)
		br_fdb_insert(p->br, p, skb->mac.ethernet->h_source, 0);

	if (p->br->stp_enabled &&
	    !memcmp(dest, bridge_ula, 5) &&
	    !(dest[5] & 0xF0)) {
		if (!dest[5]) {
			NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev, 
				NULL, br_stp_handle_bpdu);
			rcu_read_unlock();
			return 0;
		}
	}

	else if (p->state == BR_STATE_FORWARDING) {
		if (br_should_route_hook && br_should_route_hook(&skb)) {
			rcu_read_unlock();
			return -1;
		}

		if (!memcmp(p->br->dev->dev_addr, dest, ETH_ALEN))
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);
		rcu_read_unlock();
		return 0;
	}

err:
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}

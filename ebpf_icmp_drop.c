/*
 * This program is a test to block ping command for the host
 */

#include <stddef.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "bpf_helpers.h"

typedef struct {
	__u32 sip;
	__u32 dip;
} conn;

struct bpf_map_def SEC("maps/block_map") block_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(conn),
	.value_size = sizeof(conn),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

SEC("cgroup/skb")
int block_icmp_session(struct __sk_buff *skb)
{
	struct iphdr iph;
	bpf_skb_load_bytes(skb, 0, &iph, sizeof( struct iphdr));
	
	if (iph.protocol == 0x01)
	{
		__u8 type = 0;
		bpf_skb_load_bytes(skb, sizeof(struct iphdr) + offsetof(struct icmphdr, type), &type, sizeof(type));

		conn key;
		if (type == 0) { // response 
				key.sip = iph.daddr;
				key.dip = iph.saddr;
		} else if (type == 8) {  //request
				key.sip = iph.saddr;
				key.dip = iph.daddr;
		} else { // others maybe do not need to drop, TODO
				key.sip = iph.saddr;
				key.dip = iph.daddr;
		}
		
		bpf_map_update_elem(&block_map, &key, &key, 0);
		
		//return 0 means to drop packets. If this is done, icmp packets are drop,
		//and the commond 'ping' can not be used
		return 0;
	} 
	
	// don't drop
	return 1;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;


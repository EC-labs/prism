#ifndef __DISCOVERY_H
#define __DISCOVERY_H

#define EXTEND_SIZE 8 

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

struct discovery_context {
    __u64 ino_id;
    __u32 iphdr_offset;
    __u16 eth_protocol;
};

#endif /* __DISCOVERY_H */

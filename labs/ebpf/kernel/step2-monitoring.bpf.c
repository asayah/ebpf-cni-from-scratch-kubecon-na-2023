#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define ETH_P_IP 0x0800
#define MAX_ENTRIES 1000



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} counter SEC(".maps");


SEC("xdp")
int precess_xdp(struct xdp_md *ctx)
{

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
   
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        // If not a valid iph, we abort. 
        return XDP_ABORTED;

    bpf_printk("Got TCP packet from %x", bpf_ntohl(iph->saddr));
    bpf_printk("Got TCP packet to %x", bpf_ntohl(iph->daddr));


    __u32 src_ip_key = iph->saddr;

    // Write the source IP address into the map
    __u64 *value = bpf_map_lookup_elem(&counter, &src_ip_key);
    if (value) {
        // Update the existing entry
        (*value)++;
    } else {
        // Create a new entry
        __u64 one = 1;
        bpf_map_update_elem(&counter, &src_ip_key, &one, BPF_NOEXIST);
    }

   return XDP_PASS;
}   
char _license[] SEC("license") = "GPL";




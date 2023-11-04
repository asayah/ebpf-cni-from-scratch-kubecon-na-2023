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


struct ip_pair {
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ip_pair);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} iprules SEC(".maps");


SEC("xdp")
int precess_xdp(struct xdp_md *ctx)
{
    /*
    This first section is the same as the previous exercise, we are making sure that the packet received is ready to be processed 
    */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
   
   /*
   In the following section we are parsing iph, to get the the source ip of the incoming packet. 
   */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        // If not a valid iph, we abort. 
        return XDP_ABORTED;

    bpf_printk("Got TCP packet from %x", bpf_ntohl(iph->saddr));
    bpf_printk("Got TCP packet to %x", bpf_ntohl(iph->daddr));

        // Create a map lookup key (you can customize this as needed)
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

    struct ip_pair ip_pair_key;
    ip_pair_key.saddr = bpf_ntohl(iph->saddr);
    ip_pair_key.daddr = bpf_ntohl(iph->daddr);
    
    int *value_ip_pair = bpf_map_lookup_elem(&iprules, &ip_pair_key);
    if (value_ip_pair && *value_ip_pair == 1)  {
        // Update the existing entry
         return XDP_DROP;
    } else 
    {
    int zero = 0;
     bpf_map_update_elem(&iprules, &ip_pair_key, &zero, BPF_NOEXIST);   
    }    

   return XDP_PASS;
}   
char _license[] SEC("license") = "GPL";




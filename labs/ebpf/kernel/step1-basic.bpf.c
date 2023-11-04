#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define ETH_P_IP 0x0800



/* This define the section where the program will be attached. */
SEC("xdp")
int precess_xdp(struct xdp_md *ctx)
{

    /* depending at which level we are attaching the eBPF program we can have more or less data, in XDP we receive the xdp_md struct with connection data. 
     we parse the packet start and end */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* we parse the data as eth data */
    struct ethhdr *eth = data;
    
    /* if the same of the data is not of the eth data than it's a bad packet and we drop it using XDP_ABORTED */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    /* if the data is not IPV4 than process */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
   
    /* Extracting the ip header */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        /* If not a valid iph, we abort. */
        return XDP_ABORTED;

    /* Now we can just print the data we received in the logs. */

    bpf_printk("Got TCP packet from %x", bpf_ntohl(iph->saddr));
    bpf_printk("Got TCP packet to %x", bpf_ntohl(iph->daddr));

   return XDP_PASS;
}   
char _license[] SEC("license") = "GPL";




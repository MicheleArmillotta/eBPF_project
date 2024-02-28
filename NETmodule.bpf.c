#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>



#define MAX_ENTRIES 5


//RECEIVE IP and PORTS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 file da proteggere per questa syscall
    __type(key, __u32);
	__type(value, __u32);
} RECEIVE_IP_MAP SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 proc esenti per questa syscall
    __type(key, __u16);
	__type(value, __u32);
} RECEIVE_PORT_MAP SEC(".maps") ;

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {

    if (ctx->ingress_ifindex != 0) {
        
        int *value_ip;
        int *value_port;
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        __u64 nh_off;
        struct ethhdr *eth = data;
        nh_off = sizeof(*eth);
        if (data + nh_off > data_end)
            return XDP_DROP;

        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = data + nh_off;
        if (ip + 1 > data_end)
            return XDP_DROP;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 > data_end)
                return XDP_DROP;
            
            // Indirizzo IP sorgente
            __u32 src_ip = ip->saddr;
            
            // Porta destinazione TCP
            __u16 src_port =bpf_ntohs(tcp->dest);
            

            //DEBUG

            bpf_printk("IP: %d\n", src_ip);
            bpf_printk("PORT: %u\n", src_port);
            
            // Fai qualcosa con l'indirizzo IP sorgente e la porta
            value_ip = bpf_map_lookup_elem(&RECEIVE_IP_MAP,&src_ip);

            value_port = bpf_map_lookup_elem(&RECEIVE_PORT_MAP,&src_port);

            if((value_ip && (*value_ip) > 0) || (value_port && (*value_port) > 0)){
                bpf_printk("droppo un pacchetto TCP\n");
                return XDP_DROP;
            } 


        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if (udp + 1 > data_end)
                return XDP_DROP;
            
            // Indirizzo IP sorgente
            __u32 src_ip = ip->saddr;
            
            // Porta destinazione UDP
            __u16 src_port = udp->dest;

            //DEBUG

            bpf_printk("IP: %d\n", src_ip);
            bpf_printk("PORT: %u\n", src_port);
            
            // Fai qualcosa con l'indirizzo IP sorgente e la porta
            value_ip = bpf_map_lookup_elem(&RECEIVE_IP_MAP,&src_ip);

            value_port = bpf_map_lookup_elem(&RECEIVE_PORT_MAP,&src_port);

            if((value_ip && (*value_ip) > 0) || (value_port && (*value_port) > 0)){
                bpf_printk("droppo un pacchetto TCP\n");
                return XDP_DROP;
            } 
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

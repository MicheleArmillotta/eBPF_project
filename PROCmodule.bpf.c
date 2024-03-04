#include <vmlinux.h>
//#include <linux/bpf.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 100
#define MAX_ENTRIES 5

//PROCESS and TRESHOLDS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 file da proteggere per questa syscall
    __type(key, char[MAX_PATH_LEN]);
	__type(value, __u32);
} PROC_TRESH SEC(".maps") ;

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int uprobe_malloc(struct pt_regs *ctx)
{
    
    int *value_tresh;
    char comm[MAX_PATH_LEN]={0};
    size_t size = ctx->di;
   
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_printk("comm: %s\n", comm);
    value_tresh = bpf_map_lookup_elem(&PROC_TRESH,&comm); 
    
    
    if (value_tresh != NULL){
        bpf_printk("value tresh: %d ,comm: %s\n", *value_tresh,comm);
        // Leggi il parametro 'size' direttamente dalla memoria
        //bpf_probe_read_user(&size, sizeof(size), (void *)(ctx + 16)); // Assume che size sia il primo parametro
        bpf_printk("comm: %s, size: %d\n",comm,size);
        if (size > (*value_tresh)) {
            bpf_send_signal(9); //kill the current process
            bpf_printk("ho killato il processo: %s\n",comm);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

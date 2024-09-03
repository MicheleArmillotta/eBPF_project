#include <vmlinux.h>
//#include <linux/bpf.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 5
#define MAX_PATH_LEN 100

struct thresholds {
    __u32 tresh;
    __u32 forks;
} __attribute__((packed));

//PROCESS and TRESHOLDS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 processi
    __type(key, char[MAX_PATH_LEN]);
	__type(value, struct thresholds);
} FORK_TRESH SEC(".maps") ;




SEC("tracepoint/syscalls/sys_enter_fork")
int tracepoint__syscalls__sys_enter_fork(struct race_event_raw_sys_enter *ctx) {
    unsigned long addr ;
    
    
    struct thresholds *value_tresh;
    char comm[MAX_PATH_LEN]={0};
   
   
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_printk("comm: %s\n", comm);
    value_tresh = bpf_map_lookup_elem(&FORK_TRESH,&comm); 
    
    
    if (value_tresh != NULL){
        bpf_printk("value tresh: %d ,comm: %s\n", value_tresh->tresh,comm);
        
        if (value_tresh->tresh > value_tresh->forks) {
            bpf_send_signal(9); //kill the current process
            bpf_printk("ho killato il processo: %s\n",comm);
        }
        else{
            struct thresholds newValue;
            newValue.tresh = value_tresh->tresh;
            newValue.forks = value_tresh->forks + 1;
            bpf_map_update_elem(&FORK_TRESH, &comm, &newValue, BPF_ANY);
        }
    }

    
    
    return 0;
}




char _license[] SEC("license") = "GPL";

#include <vmlinux.h>
//#include <linux/bpf.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 100
#define MAX_ENTRIES 5


//PROCESS map

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 file da proteggere per questa syscall
    __type(key, char[MAX_PATH_LEN]);
	__type(value, __u32);
} PROC_MAP SEC(".maps") ;



SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct race_event_raw_sys_enter *ctx) {
    
    
    int *value;
    char comm[MAX_PATH_LEN]={0};
   
   
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_printk("comm: %s\n", comm);
    value = bpf_map_lookup_elem(&PROC_MAP,&comm); 
    
    
    if (value != NULL && *value == 1){
        bpf_send_signal(9); //kill the current process
        bpf_printk("ho killato il processo: %s\n",comm);
    }

    
    
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct race_event_raw_sys_enter *ctx) {
    
    
    int *value;
    char comm[MAX_PATH_LEN]={0};
   
   
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_printk("comm: %s\n", comm);
    value = bpf_map_lookup_elem(&PROC_MAP,&comm); 
    
    
    if (value != NULL && *value == 1){
        bpf_send_signal(9); //kill the current process
        bpf_printk("ho killato il processo: %s\n",comm);
    }

    
    
    return 0;
}



char _license[] SEC("license") = "GPL";

#include <vmlinux.h>
//#include <linux/bpf.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 100
#define MAX_ENTRIES 5

struct sys_enter_mmap_args {
    char _[16];
    long addr;
    long length;
    long prot;
    long flags;
    long fd;
    long off;
};

//PROCESS and TRESHOLDS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 file da proteggere per questa syscall
    __type(key, char[MAX_PATH_LEN]);
	__type(value, __u32);
} PROC_TRESH SEC(".maps") ;

//malloc allocation

/*SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
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
}*/

//syscall allocation

//nota: puo essere che le malloc vengano implementate anche con brk, ma non abbiamo l apossibilita
//in ebpf di ottenere il limite della memoria dedicata ai dati di un processo


SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct sys_enter_mmap_args *ctx) {
    //unsigned long addr ;
    size_t size ;

    size = (size_t)ctx->length;
    
    int *value_tresh;
    char comm[MAX_PATH_LEN]={0};
   
   
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


/*SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct pt_regs *ctx) {
    
    size_t size=ctx->si ;

    //bpf_probe_read_user(&size, sizeof(size), (size_t*)ctx->args[2]);
    
    int *value_tresh;
    char comm[MAX_PATH_LEN]={0};
   
   
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
}*/

char _license[] SEC("license") = "GPL";

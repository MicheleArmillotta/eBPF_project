#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <asm/rwonce.h>
#include <linux/jhash.h>







#define MAX_PATH_LEN 100
#define MAX_ENTRIES 5


//OPEN FILES AND PROCESSES

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 file da proteggere per questa syscall
    __type(key, __u32);
	__type(value, __u32);
} OPEN_FILES_MAP SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 proc esenti per questa syscall
    __type(key, __u32);
	__type(value, __u32);
} OPEN_PROC_MAP SEC(".maps") ;



SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    int flag_process=1; //1 vuol dire che il processo corrente non è un processo che puo fare l'azione
    int flag_path=0; //1 vuol dire che il path del file è il path non consentito
    int *value_file;
    int *value_proc;
    char comm[MAX_PATH_LEN];
    char filename[MAX_PATH_LEN];
    __u32 hash_file;
    __u32 hash_proc;
        
        //otteniamo percorso del file
    bpf_probe_read_user(filename, sizeof(filename), (char*)ctx->args[1]);
        //otteniamo nome del processo
    bpf_get_current_comm(comm, sizeof(comm));

        // Ora puoi fare ciò che vuoi con il nome del file e il nome del processo
    hash_proc= jhash(comm, MAX_PATH_LEN, 0);
    hash_file= jhash(filename, MAX_PATH_LEN, 0);

    value_file = bpf_map_lookup_elem(&OPEN_FILES_MAP,&hash_file);

    value_proc = bpf_map_lookup_elem(&OPEN_PROC_MAP,&hash_proc); 

    //bpf_printk("File aperto: %d, Processo: %d\n", *value_file,*value_proc); 
    
    if(value_file != NULL && *value_file > 0)
        flag_path=1;
    
    if(value_proc != NULL && *value_proc > 0)
        flag_process=0;
        


    if(flag_path==1 && flag_process==1){
        bpf_printk("un accesso negato");
        return -EACCES;
        
    }
    else{
        
        return 0;
    }
}

char _license[] SEC("license") = "GPL";

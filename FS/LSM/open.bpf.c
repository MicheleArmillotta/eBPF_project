#include <vmlinux.h>
//#include <linux/bpf.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/jhash.h>


#define MAX_PATH_LEN 100
#define MAX_ENTRIES 5

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 inodes da proteggere per questa syscall
    __type(key, __UINT64_TYPE__);  //inodes unsigned long
	__type(value, __u32);
} OPEN_FILES_INODE_MAP SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); //max 5 proc esenti per questa syscall
    __type(key, char[MAX_PATH_LEN]);
	__type(value, __u32);
} OPEN_PROC_MAP SEC(".maps") ;


SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0)
    {
        return ret;
    }

    int retVal;
    int flag_process=1; //1 vuol dire che il processo corrente non è un processo che puo fare l'azione
    int flag_path=0; //1 vuol dire che il path del file è il path non consentito
    int *value_file;
    int *value_proc;
    char comm[MAX_PATH_LEN]={0};
    //char filename[MAX_PATH_LEN]={0};
    
    struct inode *inode = file->f_inode;
    unsigned long inode_from_struct = inode->i_ino;
    
    
    
    //otteniamo nome del processo
    
    bpf_get_current_comm(comm, sizeof(comm));
    
    

    
    bpf_printk("File aperto(inode): %lu, Processo: %s\n",inode_from_struct,comm);
        // Ora puoi fare ciò che vuoi con il nome del file e il nome del processo
    
    
    value_file = bpf_map_lookup_elem(&OPEN_FILES_INODE_MAP,&inode_from_struct);

    value_proc = bpf_map_lookup_elem(&OPEN_PROC_MAP,&comm); 


    

    bpf_printk("File aperto: %d, Processo: %d\n", value_file,value_proc); 
    
    if(value_file && (*value_file > 0)){
        flag_path=1;
        bpf_printk("sono dentro\n");}
    
    if(value_proc && (*value_proc > 0))
        flag_process=0;
        
   
    
    
    if(flag_path==1 && flag_process==1){
        bpf_printk("un accesso negato\n");
        return -EPERM;
        
    }
    else{
        
        return 0;
    }


}

char _license[] SEC("license") = "GPL";

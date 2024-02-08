// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h> 


#define MAX_PATH_LEN 100
#define MAX_PROCESSES 10
#define MAX_FILES_PER_KEY 10
#define MAX_ENTRIES 6
#define MAX_KEY 10

struct file_and_process_list {
    char file_paths[MAX_FILES_PER_KEY][MAX_PATH_LEN];
    char process_paths[MAX_PROCESSES][MAX_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
    __type(key, sizeof(char[MAX_KEY]));
	__type(value, sizeof(struct file_and_process_list));
} file_and_process_map SEC(".maps") ;



SEC("kprobe/vfs_open")
int kprobe_vfs_open(struct pt_regs *ctx)
{
    int flag_process=1; //1 vuol dire che il processo corrente non è un processo che puo fare l'azione
    int flag_path=0; //1 vuol dire che il path del file è il path non consentito
    char current_event[MAX_KEY] = "open"; // Esempio di evento
    struct file_and_process_list *list; // Elenco dei percorsi dei file e dei processi consentiti per la chiave corrente

    // Ottieni l'elenco dei percorsi dei file e dei processi consentiti dalla mappa BPF
    list = bpf_map_lookup_elem(&file_and_process_map, &current_event);

    if(list){
        
        char comm[MAX_PATH_LEN];
        char filename[MAX_PATH_LEN];

        //otteniamo percorso del file
        bpf_probe_read_user(filename, sizeof(filename), (void *)PT_REGS_PARM1(ctx));
        //otteniamo nome del processo
        bpf_get_current_comm(comm, sizeof(comm));

        
        bpf_printk("File aperto: %s, Processo: %s\n", filename, comm);

        

        
        for (int i = 0; i < MAX_PROCESSES; i++) {
            int j;
            for (j = 0; j < MAX_PATH_LEN; j++) {
                if (comm[j] != list->process_paths[i][j]) {
                    break;
                }
                if (comm[j] == '\0' && list->process_paths[i][j] == '\0') {
                    flag_process = 0;
                    break;
                }
            }
            if (flag_process == 0) {
                break;
            }
        }

            if (flag_process == 1) {
                for (int i = 0; i < MAX_FILES_PER_KEY; i++) {
                    int j;
                    for (j = 0; j < MAX_PATH_LEN; j++) {
                        if (filename[j] != list->file_paths[i][j]) {
                            break;
                        }
                        if (filename[j] == '\0' && list->file_paths[i][j] == '\0') {
                            flag_path = 1;
                            break;
                        }
                    }
                    if (flag_path == 1) {
                        break;
                    }
                }
            }
        }


    if(flag_path==1 && flag_process==1){
        bpf_printk("un accesso negato");
        return -EACCES;
        
    }
    else{
        bpf_printk("un accesso riuscito");
        return 0;
    }
}

char _license[] SEC("license") = "GPL";

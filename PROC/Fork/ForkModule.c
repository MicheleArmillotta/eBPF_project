#include <linux/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/resource.h>
#include <stddef.h>
#include "PROCForkModule.skel.h"



#define MAX_LINE_LENGTH 256
#define MAX_PATH_LEN 100
#define MAX_PROC 5

static volatile sig_atomic_t stop;


struct thresholds {
    __u32 tresh;
    __u32 forks;
} __attribute__((packed));

static void sig_int(int signo)
{
	stop = 1;
}



void bump_memlock_rlimit() {
    struct rlimit rlim;

    if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;  // Imposta il limite corrente al massimo consentito
        if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
            perror("setrlimit");
            exit(-1);
        }
    } else {
        perror("getrlimit");
        exit(-1);
    }
}

//popolare la mappa

int populate_map(const char *config_file, struct bpf_map *map_proc, char *type) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Error opening configuration file");
        return 1;
    }
    char line[MAX_LINE_LENGTH];
    char current_type[MAX_LINE_LENGTH];
    int ret;
    
    while (fgets(line, sizeof(line), file)) {
        // Rimuove il carattere newline, se presente
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        // Analizza la riga per tipo, percorsi dei file e nomi dei processi
        
        char proc_names[MAX_PATH_LEN];
        char proc_name[MAX_PATH_LEN];
        char proc_names_array[MAX_PROC][MAX_PATH_LEN];
        char proc_treshes[MAX_PATH_LEN];
        char proc_tresh[MAX_PATH_LEN];
        int proc_tresh_int;
        struct thresholds value;

        if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, proc_names) != 2)
            continue;

        // Se il tipo corrente corrisponde al tipo richiesto
        if (strcmp(current_type, type) == 0) {
            char *token;
            int i=0;
            // Estrae percorsi dei file
            token = strtok(proc_names, ",;");
            while (token != NULL) {
                // Popola la mappa dei file
                
                memset(proc_name, 0, sizeof(proc_name));
                strcpy(proc_name,token);
                printf("DEBUG => procName: %s; \n", proc_name);
                memset(proc_names_array[i], 0, sizeof(proc_names_array[i]));
                strcpy(proc_names_array[i],proc_name);
                i++;
                token = strtok(NULL, ",;");
            }
            if(fgets(line, sizeof(line), file) != NULL){
                // Estrae nomi dei processi
                if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, proc_treshes) != 2)
                    continue;
                int i=0;
                token = strtok(proc_treshes, ",;");
                while (token != NULL) {
                    // Popola la mappa dei processi
                    
                    memset(proc_tresh, 0, sizeof(proc_name));
                    strcpy(proc_tresh,token);
                    proc_tresh_int=atoi(proc_tresh);
                    printf("DEBUG => threshold: %d; \n", proc_tresh_int);
                    value.forks=0;
                    value.tresh=proc_tresh_int;
                    ret = bpf_map__update_elem(map_proc,proc_names_array[i],sizeof(proc_names_array[i]),&value,sizeof(value),BPF_ANY);
                    if (ret < 0) {
                    // Errore nell'aggiornamento dell'elemento
                    fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                    return ret;
                    }
                    i++;
                    token = strtok(NULL, ",;");
                }
            }
            else{
                return -1;
            }

            // Poiché ogni tipo può essere presente una sola volta,
            // possiamo interrompere la scansione dopo aver trovato il tipo corrispondente
            break;
        }
    }

    fclose(file);
    return 0;

    
}

int main(int argc, char **argv)
{
	
    struct PROCForkModule_bpf *skel;
    struct bpf_map *map_proc;
	int err;

	
	/* Open load and verify BPF application */
	skel = PROCForkModule_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}


	/* Attach tracepoint handler */
	err = PROCForkModule_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    // Ottieni le mappa BPF per la OPEN
    map_proc = skel->maps.FORK_TRESH;
    if (map_proc < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    
    //popolo la mappa
    if((populate_map("ForkConfig.txt",map_proc,"Fork"))!=0){
        fprintf(stderr, "Errore nel popolare la mappa \n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler\n");
		goto cleanup;
	}

	printf("Successfully started! pleas type ctrl+C for shutting down the module \n ");

	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}



cleanup:
	PROCForkModule_bpf__destroy(skel);
	return -err;

}

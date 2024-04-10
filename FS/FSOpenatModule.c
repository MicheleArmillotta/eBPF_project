#include <linux/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/resource.h>
#include <stddef.h>
#include "FSmodule.skel.h"


#define MAX_LINE_LENGTH 256
#define MAX_PATH_LEN 100


static volatile sig_atomic_t stop;

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

int populate_map(const char *config_file, struct bpf_map *map_file, struct bpf_map *map_proc, char *type) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Error opening configuration file");
        return 1;
    }
    char line[MAX_LINE_LENGTH];
    char current_type[MAX_LINE_LENGTH];
    __u32 ok_value=1;
    int ret;
    
    while (fgets(line, sizeof(line), file)) {
        // Rimuove il carattere newline, se presente
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        // Analizza la riga per tipo, percorsi dei file e nomi dei processi
        char file_paths[MAX_PATH_LEN];
        char proc_names[MAX_PATH_LEN];
        char file_path[MAX_PATH_LEN];
        char proc_name[MAX_PATH_LEN];
        if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, file_paths) != 2)
            continue;

        // Se il tipo corrente corrisponde al tipo richiesto
        if (strcmp(current_type, type) == 0) {
            char *token;
            // Estrae percorsi dei file
            token = strtok(file_paths, ",;");
            while (token != NULL) {
                // Popola la mappa dei file
                
                memset(file_path, 0, sizeof(file_path));
                strcpy(file_path,token);
                printf("DEBUG => filePath: %s; \n", file_path);
                ret = bpf_map__update_elem(map_file,file_path,sizeof(file_path),&ok_value,sizeof(ok_value),BPF_ANY);
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                return ret;
                }
                token = strtok(NULL, ",;");
            }
            if(fgets(line, sizeof(line), file) != NULL){
                // Estrae nomi dei processi
                if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, proc_names) != 2)
                    continue;

                token = strtok(proc_names, ",;");
                while (token != NULL) {
                    // Popola la mappa dei processi
                    
                    memset(proc_name, 0, sizeof(proc_name));
                    strcpy(proc_name,token);
                    printf("DEBUG => proc: %s; \n", proc_name);
                    
                    ret = bpf_map__update_elem(map_proc,proc_name,sizeof(proc_name),&ok_value,sizeof(ok_value),BPF_ANY);
                    if (ret < 0) {
                    // Errore nell'aggiornamento dell'elemento
                    fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                    return ret;
                    }
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
	struct FSmodule_bpf *skel;
    struct bpf_map *map_file;
    struct bpf_map *map_proc;
	int err;

	
	/* Open load and verify BPF application */
	skel = FSmodule_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = FSmodule_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    // Ottieni le mappa BPF per la OPEN
    map_file = skel->maps.OPEN_FILES_MAP;
    if (map_file < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    map_proc = skel->maps.OPEN_PROC_MAP;
    if (map_proc < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    //popolo la mappa
    if((populate_map("config.txt",map_file,map_proc,"open"))!=0){
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
	FSmodule_bpf__destroy(skel);
	return -err;

}

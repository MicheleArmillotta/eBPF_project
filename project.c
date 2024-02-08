#include <linux/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/resource.h>
#include <stddef.h>
#include "project.skel.h"


#define MAX_FILES_PER_KEY 10
#define MAX_KEY 10 //massima lunghezza della chiave
#define MAX_PROCESSES 10
#define MAX_PATH_LEN 100
#define MAX_KEYS 6 // Massimo numero di chiavi nel file di configurazione

struct file_and_process_list {
    char file_paths[MAX_FILES_PER_KEY][MAX_PATH_LEN];
    char process_paths[MAX_PROCESSES][MAX_PATH_LEN];
};

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

int populate_map(const char *config_file, struct bpf_map *map) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Error opening configuration file");
        return 1;
    }

    char line[100];
    char key[MAX_KEYS][MAX_KEY];
    struct file_and_process_list list[MAX_KEYS];
    int file_index = 0;
    int process_index = 0;

    int key_index = 0; // Inizializza key_index a 0 all'inizio della funzione

while (fgets(line, sizeof(line), file)) {
    if (sscanf(line, "[%[^]]]", key[key_index]) == 1) {
        printf("DEBUG => key: %s", key[key_index]);
        // Memorizza la lista attuale nel suo indice corrispondente
        if (key_index < MAX_KEYS) {
            memset(&list[key_index], 0, sizeof(struct file_and_process_list));
            file_index = 0;
            process_index = 0;
            key_index++; // Incrementa key_index ogni volta che leggi una nuova chiave
        } else {
            printf("Numero massimo di chiavi raggiunto\n");
            break;
        }
    } else if (strstr(line, "trusted processes:")) {
        char *token = strtok(line, ":"); // Separa la linea fino al primo ":"
        token = strtok(NULL, ",;"); // Continua a dividere la stringa utilizzando "," e ";" come delimitatori
        while (token != NULL && strchr(token, ';') == NULL) {
            printf("DEBUG => process: %s", token);
            strcpy(list[key_index - 1].process_paths[process_index++], token);
            token = strtok(NULL, ",;");
        }
    } else if (strstr(line, "protected files:")) {
        char *token = strtok(line, ":"); // Separa la linea fino al primo ":"
        token = strtok(NULL, ",;"); // Continua a dividere la stringa utilizzando "," e ";" come delimitatori
        while (token != NULL && strchr(token, ';') == NULL) {
            printf("DEBUG => file: %s", token);
            strcpy(list[key_index - 1].file_paths[file_index++], token);
            token = strtok(NULL, ",;");
        }
    }
}


     fclose(file);

     // Update BPF map with the data read from configuration file
    for (int i = 0; i < key_index; ++i) {
        
        
        int ret = bpf_map__update_elem(map,&key[key_index], sizeof(key[i]),&list[i], sizeof(list[i]),BPF_ANY);
        if (ret) {
            perror("Error updating BPF map");
            return 1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
	struct project_bpf *skel;
    struct bpf_map *map;
	int err;

	
	/* Open load and verify BPF application */
	skel = project_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = project_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    // Ottieni la mappa BPF
    map = skel->maps.file_and_process_map;
    if (map < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }

    //popolo la mappa

    if((populate_map("config.txt",map))!=0){
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
	project_bpf__destroy(skel);
	return -err;

}

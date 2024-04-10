// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <libbpf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <bpf.h>

#include "NETmodule.skel.h"
#include <linux/types.h>

int INTERFACE;
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

int populate_map(const char *config_file, struct bpf_map *map_ip, struct bpf_map *map_port, char *type) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Error opening configuration file");
        return 1;
    }
    char line[MAX_LINE_LENGTH];
    char current_type[MAX_LINE_LENGTH];
    int ok_value=1;
    int ret;
    
    while (fgets(line, sizeof(line), file)) {
        // Rimuove il carattere newline, se presente
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        // Analizza la riga per tipo, percorsi dei file e nomi dei processi
        char ips[MAX_PATH_LEN];
        char ports[MAX_PATH_LEN];
        char ip[MAX_PATH_LEN];
        char port[MAX_PATH_LEN];
        char interface[MAX_PATH_LEN];
        __U32_TYPE ip_u32 = 0; 
        __U16_TYPE port_u16 = 0;

        if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, ips) != 2)
            continue;

        // Se il tipo corrente corrisponde al tipo richiesto
        if (strcmp(current_type, type) == 0) {
            char *token;
            // Estrae percorsi dei file
            token = strtok(ips, ",;");
            while (token != NULL) {
                // Popola la mappa dei file
                
                memset(ip, 0, sizeof(ip));
                strcpy(ip,token);
                
                if (inet_pton(AF_INET, ip, &ip_u32) != 1) {
                    fprintf(stderr, "Errore nella conversione dell'indirizzo IP.\n");
                    return 1;
                }
                printf("DEBUG => ip: %d; \n", ip_u32);

                ret = bpf_map__update_elem(map_ip,&ip_u32,sizeof(ip_u32),&ok_value,sizeof(ok_value),BPF_ANY);
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                return ret;
                }
                token = strtok(NULL, ",;");
            }
            if(fgets(line, sizeof(line), file) != NULL){
                // Estrae nomi dei processi
                if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, ports) != 2)
                    continue;

                token = strtok(ports, ",;");
                while (token != NULL) {
                    // Popola la mappa dei processi
                    
                    memset(port, 0, sizeof(port));
                    strcpy(port,token);
                    port_u16= (uint16_t)atoi(port);

                   printf("DEBUG => port: %d; \n", port_u16);
                    
                    ret = bpf_map__update_elem(map_port,&port_u16,sizeof(port_u16),&ok_value,sizeof(ok_value),BPF_ANY);
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
            if(fgets(line, sizeof(line), file) != NULL){
                // PER LE INTERFACCE
                if (sscanf(line, "%[^.].%*[^:]: %[^\n]", current_type, interface) != 2)
                    continue;

                token = strtok(interface, ",;");
                while (token != NULL) {
                    // Popola la mappa dei processi
                    
                   INTERFACE = atoi(interface);

                   printf("DEBUG => interface: %d; \n", INTERFACE);
                    
                    
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
    int fd;
    struct bpf_xdp_attach_opts *xdp_opts=malloc(sizeof(struct bpf_xdp_attach_opts));
	struct NETmodule_bpf *skel;
    struct bpf_map *map_ip;
    struct bpf_map *map_port;
	int err;

	
	/* Open load and verify BPF application */
	skel = NETmodule_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    // Ottieni le mappa BPF per la OPEN
    map_ip = skel->maps.RECEIVE_IP_MAP;
    if (map_ip < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    map_port = skel->maps.RECEIVE_PORT_MAP;
    if (map_port < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    //popolo la mappa
    if((populate_map("NETconfig.txt",map_ip,map_port,"receive"))!=0){
        fprintf(stderr, "Errore nel popolare la mappa \n");
        goto cleanup;
    }

    fd = bpf_program__fd(skel->progs.xdp_ingress);
    xdp_opts->sz = sizeof(struct bpf_xdp_attach_opts);
    xdp_opts->old_prog_fd=-1;
    err = bpf_xdp_attach(INTERFACE,fd,BPF_ANY,xdp_opts);
	if (err) {
		fprintf(stderr, "Failed to attach XDP: %d\n", err);
		goto cleanup;
	}
    xdp_opts->old_prog_fd=fd;

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
    bpf_xdp_detach(INTERFACE, BPF_ANY,xdp_opts);        
	NETmodule_bpf__destroy(skel);
	return -err;

}

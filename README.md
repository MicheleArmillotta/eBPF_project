# eBPF Experiments
This repository contains a series of experiments exploring various capabilities of eBPF (Extended Berkeley Packet Filter), 
in particular, we try to exploit the technology to block potentially malicious actions, instead of simply monitoring the system.
Below is a brief description of each experiment and what it aims to achieve.

## File system experiments
### System call Openat
This experiment uses eBPF to block the openat system calls made by a specific process (configurable in the ConfigOpenat.txt file)
### LSM 
This experiment does the same thing but using LSM hooks

## NET experiments


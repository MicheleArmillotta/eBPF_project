# eBPF Experiments
This repository contains a series of experiments exploring various capabilities of eBPF (Extended Berkeley Packet Filter), 
in particular, we try to exploit the technology to block potentially malicious actions, instead of simply monitoring the system.
Below is a brief description of each experiment and what it aims to achieve.

## File system experiments
### System call Openat
This experiment uses two maps that tell the eBPF program which files protect and which processes, if any, are authorized to execute openat() on files as well specified. Whenever an open() or openat() is executed, the program eBPF is activated, checks whether the target file and the calling process are present in the respective maps, and makes decisions accordingly, possibly directing the system call to a file containing an error message
### LSM 
This experiment does the same thing but using LSM hooks

## NET experiments


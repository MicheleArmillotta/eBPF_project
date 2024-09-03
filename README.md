#eBPF Experiments
This repository contains a series of experiments exploring various capabilities of eBPF (Extended Berkeley Packet Filter).
Below is a brief description of each experiment and what it aims to achieve.

##File system experiments
###System call Openat
This experiment uses eBPF to block the openat system calls made by a specific process (configurable in the file)

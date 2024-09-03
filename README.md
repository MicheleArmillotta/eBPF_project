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
For the experiment that deals with protection from unwanted traffic, an example has been implemented that filters network packets that do not come from the IP addresses specified in the configuration file, or that do not point to the desired ports. This information about the IP address and port whitelists is communicated to the kernel-space always through eBPF maps. When any packet arrives on the network card, the eBPF program is activated and analyzes the packet and the protocol used. If it is a TCP or UDP packet, the IP address and the port are compared with those present in the maps, discarding the packets that do not find a match.

## Process experiments

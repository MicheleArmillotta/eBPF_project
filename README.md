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
### Mmap
This experiment is part of the module that manages and limits certain processes; it allows to specify a threshold (expressed in bytes) and a target process, so that the latter is killed if it tries to allocate more dynamic memory than the specified one. Again, the configuration specifications are communicated to the kernel-space part of the example through eBPF maps. Every time mmap() is called in the system, the eBPF program is executed, checks the calling process and how much memory it is trying to allocate, and eventually kills the process that exceeds the specified threshold.
### Net
In this case the experiment tries to limit the access of a process to some network resources by filtering the system calls recvfrom() and sendto(). Inside the configuration file only the target processes will be specified, then communicated to the eBPF program through maps. The eBPF program simply terminates the processes that call one of these two system calls, if they are present inside the map, thus blocking the communications of datagrams. This is just a small example of what could be done by exploiting all the system calls that regulate the communication of processes with the network (such as connect(), recv(), bind(), etc..), in fact one could think of solutions that manage the different situations in a more specific and customizable way.
### Fork
**not working**

This experiment deals with limiting the number of child processes that can be generated by a process, filtering the fork() system call. In this case the program is configurable by specifying the parent processes to monitor and the number of children that each of them can generate; as can be imagined, this information will be passed from the user space to the kernel space through eBPF maps. The latter are also used by the example to maintain a state relating to the number of fork()s executed by each process; if this number exceeds the threshold established by the configuration, the process will be terminated. Controlling fork()s can be very useful to better manage the system resources, allocating them in a fair and safe way. It can also be used to prevent malicious events or attacks such as the "fork bomb".




![ScreenshotDoc (107)](https://github.com/user-attachments/assets/48459908-61c3-48c5-96b7-97c5e697b299)



## How to Run the Experiments
For each experiment, you can find the corresponding scripts and eBPF programs in the directories. You will need to use [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) and then:
you will need to use libbpf-bootstrap and then:

1. add the name of the experiment in the Makefile
   
   `APPS = example example example`
  
2. create the executable

   `make example`
  
3. run the executable (userspace daemon)

   `sudo ./example`

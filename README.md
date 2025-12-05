# eBPF Experiments

This repository collects a set of practical experiments demonstrating how **eBPF (Extended Berkeley Packet Filter)** can be used not only for observability but also for **real-time enforcement and protection** inside the Linux kernel.  
Each experiment explores a different subsystem (file system, networking, process control) and shows how eBPF maps and hooks can be combined to implement security and resource-control policies.

A detailed scientific description of this work has been published in:

Mazzocca C., Garbugli A., Armillotta M., Montanari M., Bellavista P.,  
*Flexible and Secure Process Confinement with eBPF*,  
International Workshop on Security and Trust Management (STM), co-located with ESORICS, Bydgoszcz, Poland, September 19–20, 2024.

---

## File System Experiments

### System Call `openat`
This experiment implements a selective protection mechanism for file access.  
Two eBPF maps are used:

- a **file protection map**, listing the files to protect;  
- a **process authorization map**, listing processes permitted to invoke `open()`/`openat()` on those files.

When a monitored system call is executed, the eBPF program checks the invoking process and the target pathname. Unauthorized attempts can be redirected to an alternative file containing an error message, effectively blocking the operation.

### LSM-Based Variant
This variant provides the same behavior but relies on **Linux Security Module (LSM) hooks** instead of system call tracing.  
The logic remains identical—policy rules are stored in eBPF maps—while benefiting from a more stable and security-oriented kernel interface.

---

## Network Experiments

These experiments demonstrate how eBPF can be used to filter inbound traffic at the earliest point in the networking stack.

A configuration file defines **whitelisted IP addresses and ports**, which are loaded into eBPF maps.  
For each incoming packet, the program inspects the protocol (TCP or UDP), extracts source/destination information, and discards packets that do not match the whitelist.  
This example illustrates how eBPF can implement programmable, low-overhead network access control.

---

## Process Experiments

### `mmap` Memory Allocation Control
This experiment enforces per-process memory allocation limits.  
A threshold (in bytes) and a target process ID are stored in eBPF maps.  
The eBPF program intercepts `mmap()` calls, examines the requested allocation size, and terminates the process if it exceeds the configured threshold.  
This demonstrates how eBPF can support lightweight resource-governance mechanisms.

### Datagram Network Access Restriction
This experiment restricts process access to network primitives by filtering the system calls `recvfrom()` and `sendto()`.  
A map lists the processes subject to restriction.  
When one of the monitored calls is invoked, the eBPF program checks the caller and immediately terminates it if it appears in the map.  
Although minimal, this approach illustrates how to extend fine-grained control to additional calls such as `connect()`, `recv()`, and `bind()`.

### Fork Control (Currently Not Functional)
This experiment aims to limit the number of child processes that a parent process may create.  
Configuration includes:

- the set of parent processes to monitor;  
- the maximum allowed number of child processes per parent.

eBPF maps store both configuration and per-process counters.  
Whenever `fork()` is invoked, the program increments the counter and terminates the process if the configured threshold is exceeded.  
Such control mechanisms can mitigate resource exhaustion attacks, including fork bombs.

![ScreenshotDoc (107)](https://github.com/user-attachments/assets/48459908-61c3-48c5-96b7-97c5e697b299)

---

## How to Run the Experiments

Each experiment contains its own user-space component and eBPF program.  
To build and run them, first install **[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)**, then:

1. Add the experiment name in the `Makefile`:

   ```make
   APPS = example example example

2. create the executable

   `make example`
  
3. run the executable (userspace daemon)

   `sudo ./example`









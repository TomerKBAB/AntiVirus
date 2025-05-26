# AntiVirus

## Description
A simple menu‐driven virus scanner and neutralizer in C.  
It loads binary virus signatures into a linked list, scans a target file for matches, and “fixes” infections by overwriting the first byte of each virus instance with a RET instruction (0xC3).

## Features
- **Signature Loading:**  
  - Reads a custom binary format (magic “VIRL”/“VIRB”)  
  - Supports big- and little-endian signature files  
- **Linked-List Storage:**  
  - Dynamically stores each `Virus` struct in a generic singly linked list  
- **Detection:**  
  - Scans an in-memory buffer byte by byte  
  - Reports offset, virus name, and signature size for each match  
- **Neutralization:**  
  - Opens the infected file in read-write mode  
  - Overwrites each virus’s first byte with a RET opcode (0xC3)  
- **Clean-up:**  
  - Proper `free()` of all allocated memory for viruses, detections, and lists

## Requirements
- GCC (or any C99-compatible compiler)  
- Linux or UNIX-like OS (relies on standard C and POSIX I/O)  

## Build & Run

```bash
# Compile
gcc -std=c99 -Wall -Wextra -o AntiVirus AntiVirus.c

# Usage
./AntiVirus <infected_file>

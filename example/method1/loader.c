
#include <bpf/bpf.h> 
#include <bpf/libbpf.h> 
#include <stdio.h> 
#include <unistd.h>

int main(int argc, char **argv) {
  int prog_fd;
  struct bpf_object *obj;

  // Load program from an object file with eBPF code. Check that it was successfully loaded
  if (bpf_prog_load("pkill.o", BPF_PROG_TYPE_TRACEPOINT , &obj , & prog_fd) != 0) {
    printf("eBPF program not loaded\n");
    return -1; }

  // Check that we got a file descriptor for the loaded object file.
  if (prog_fd < 1) {
    printf("Error creating prog_fd\n"); return -2;
  }

  // Attach the eBPF program by it's function name
  struct bpf_program *prog = bpf_object__find_program_by_name(obj,"kill_example");
  bpf_program__attach(prog);
  while(1) sleep(1);
  return 0;
}

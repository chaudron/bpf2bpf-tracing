#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
  return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}


static int libbpf_debug_print(enum libbpf_print_level level,
      const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG)
    return 0;

   return vfprintf(stderr, format, args);
}


int main()
{
  int err;
  int prog_fd = -69;
  struct bpf_object *obj, *prog_obj;
  struct bpf_object_load_attr load_attr;
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

  libbpf_set_print(libbpf_debug_print);


  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
	    strerror(errno));
    return 0;
  }

  /* Mimic the load from "tools/testing/selftests/bpf/prog_tests/xdp.c" */
  err = bpf_prog_load("./xdp_pass_kern.o", BPF_PROG_TYPE_XDP, &prog_obj, &prog_fd);
  //err = bpf_prog_load("/data/linux_kernel/tools/testing/selftests/bpf/test_pkt_access.o", BPF_PROG_TYPE_UNSPEC, &prog_obj, &prog_fd);
  printf("- Found prog_fd = %d\n", prog_fd);

  if (err || prog_fd < 0) {
    printf("ERROR: Cant cat program fd, make sure hardcoded ID is ok, and ran as root!\n");
    return 0;
  }

  printf("- Opening object file\n");

  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .attach_prog_fd = prog_fd);

  obj = bpf_object__open_file("./xdp_sample_fentry_fexit_kern.o", &opts);
  //obj = bpf_object__open_file("/data/linux_kernel/tools/testing/selftests/bpf/fexit_bpf2bpf.o", &opts);
  
  if (IS_ERR_OR_NULL(obj)) {
    perror("ERROR: Failed to open trace object file");
    return 0;
  }

  printf("- Opened object file: %p\n", obj);

  memset(&load_attr, 0, sizeof(load_attr));
  load_attr.obj = obj;
  load_attr.log_level = 1 + 2 + 4;
  //err = bpf_object__load(obj);
  err = bpf_object__load_xattr(&load_attr);
  if (err < 0) {
    perror("ERROR: Failed to load object file");
    return 0;
  }



   return 0;
}

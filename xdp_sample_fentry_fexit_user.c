#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
    int                          err = 0;
    int                          prog_fd;
    struct bpf_object           *obj; //, *prog_obj;
    struct bpf_object_load_attr  load_attr;
    struct rlimit                r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_program          *trace_prog_entry;
    struct bpf_link             *trace_link_entry;
    struct bpf_program          *trace_prog_exit;
    struct bpf_link             *trace_link_exit;

    libbpf_set_print(libbpf_debug_print);

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
          fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                  strerror(errno));
        return 0;
    }

    /* Mimic the load from "tools/testing/selftests/bpf/prog_tests/xdp.c" */
    /*
     * For this to work you need to attached the xdp_pass_kern.o to a interface
     *  manually. I used the xdp-tutorial infra for doing this:
     *
     * eval $(../testenv/testenv.sh alias)
     * t setup --name veth-tst
     * ../basic01-xdp-pass/xdp_pass_user --dev veth-tst
     * bpftool prog list
     * 167: xdp  tag 3fed666785a57e53  gpl
     *     loaded_at 2019-12-05T10:33:12+0000  uid 0
     *     xlated 16B  jited 40B  memlock 4096B
     *
     * Use the ID value, 167 above, in the function below!
     */

    // err = bpf_prog_load("./xdp_pass_kern.o", BPF_PROG_TYPE_XDP,
    //                    &prog_obj, &prog_fd);

    prog_fd = bpf_prog_get_fd_by_id(167);
    printf("- Found prog_fd = %d\n", prog_fd);

    if (err || prog_fd < 0) {
        printf("ERROR: Cant cat program fd, make sure hardcoded ID is ok, and ran as root!\n");
        return 0;
    }

    printf("- Opening object file\n");

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .attach_prog_fd = prog_fd);

    obj = bpf_object__open_file("./xdp_sample_fentry_fexit_kern.o", &opts);

    if (IS_ERR_OR_NULL(obj)) {
        perror("ERROR: Failed to open trace object file");
        return 0;
    }

    printf("- Opened object file: %p\n", obj);

    memset(&load_attr, 0, sizeof(load_attr));
    load_attr.obj = obj;
    load_attr.log_level = 1 + 2 + 4;
    err = bpf_object__load_xattr(&load_attr);
    if (err < 0) {
        perror("ERROR: Failed to load object file");
        return 0;
    }

    trace_prog_entry = bpf_object__find_program_by_title(obj, "fentry/xdp_prog_simple");
    if (!trace_prog_entry) {
        perror("ERROR: Locating fentry/xdp_prog_simple");
        return 0;
    }

    printf("- Located trace program \"fentry/xdp_prog_simple\"\n");

    trace_link_entry = bpf_program__attach_trace(trace_prog_entry);
    if (!trace_link_entry) {
        perror("ERROR: Locating fentry/xdp_prog_simple");
        return 0;
    }

    printf("- Attached trace \"fentry/xdp_prog_simple\"\n");

    trace_prog_exit = bpf_object__find_program_by_title(obj, "fexit/xdp_prog_simple");
    if (!trace_prog_exit) {
        perror("ERROR: Locating fexit/xdp_prog_simple");
        return 0;
    }

    printf("- Located trace program \"fexit/xdp_prog_simple\"\n");

    trace_link_exit = bpf_program__attach_trace(trace_prog_exit);
    if (!trace_link_exit) {
        perror("ERROR: Locating fexit/xdp_prog_simple");
        return 0;
    }

    printf("- Attached trace \"fexit/xdp_prog_simple\"\n");

    printf("! Entered sleep loop, CTRL-C to exit!\n");
    while(true) {
        sleep(1);
    }

    return 0;
}

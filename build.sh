set -e

LLVM_PATH=/data/llvm-project/llvm/build/install/
KERN_PATH=/data/linux_kernel
PAHOLE=/home/vagrant/pahole/build/pahole

# Make sure CLANG is the version we need
export PATH=$LLVM_PATH/bin:$PATH
clang --version

echo "- ^^ CLANG version"

$PAHOLE --version
echo "- ^^ PAHOLE version"

# Build the pass kernel program
(clang  -I. -I$KERN_PATH/tools/testing/selftests/bpf -g \
  -D__TARGET_ARCH_x86 -mlittle-endian -I. -I./include/uapi \
  -I$KERN_PATH/tools/include/uapi -I$KERN_PATH/tools/lib/bpf \
  -I$KERN_PATH/tools/testing/selftests/usr/include \
  -idirafter /usr/local/include \
  -idirafter $LLVM_PATH/lib/clang/10.0.0/include \
  -idirafter /usr/include -Wno-compare-distinct-pointer-types \
  -O2 -target bpf -emit-llvm -c xdp_pass_kern.c -o - \
  || echo "BPF obj compilation failed") | \
    llc -mattr=dwarfris -march=bpf -mcpu=probe \
	-mattr=+alu32 -filetype=obj \
	-o xdp_pass_kern.o

echo "- Build xdp_pass_kern.o"


# Build trace program
(clang  -I. -I$KERN_PATH/tools/testing/selftests/bpf -g \
  -D__TARGET_ARCH_x86 -mlittle-endian -I. -I./include/uapi \
  -I$KERN_PATH/tools/include/uapi -I$KERN_PATH/tools/lib/bpf \
  -I$KERN_PATH/tools/testing/selftests/usr/include \
  -idirafter /usr/local/include \
  -idirafter $LLVM_PATH/lib/clang/10.0.0/include \
  -idirafter /usr/include -Wno-compare-distinct-pointer-types \
  -O2 -target bpf -emit-llvm -c xdp_sample_fentry_fexit_kern.c -o - \
  || echo "BPF obj compilation failed") | \
    llc -mattr=dwarfris -march=bpf -mcpu=probe \
	-mattr=+alu32 -filetype=obj \
	-o xdp_sample_fentry_fexit_kern.o

echo "- Build xdp_sample_fentry_fexit_kern.o"


# /data/linux_kernel/tools/lib/bpf
#    
gcc -g -Wall -O2 -DHAVE_GENHDR -I$KERN_PATH/tools/include/uapi \
    -I$KERN_PATH/tools/lib -I$KERN_PATH/tools/lib/bpf \
    -I$KERN_PATH/include/generated -I$KERN_PATH/tools/include \
    -I$KERN_PATH/tools/testing/selftests/bpf \
    -L$KERN_PATH/tools/testing/selftests/bpf \
    xdp_sample_fentry_fexit_user.c \
    -lcap -lelf -lrt -lpthread \
    -l:libbpf.a \
    -o xdp_sample_fentry_fexit_user

# Removed the below as I get errors like
#   "libbpf: Cannot find bpf_func_info for main program sec xdp_prog_simple_sec. Ignore all bpf_func_info."
# echo "- Do pahole -j on eBPF"
# $PAHOLE -J xdp_pass_kern.o
# $PAHOLE -J xdp_sample_fentry_fexit_kern.o

echo "- Build OK!"

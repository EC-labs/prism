script_d="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)"


# Given our instrumentation method in bpftrace, we need a map that 
# converts syscall numbers to their system call names
# https://unix.stackexchange.com/questions/445507/syscall-number-%E2%86%92-name-mapping-at-runtime

dict=$(
    awk '
    BEGIN { 
        print "#include <sys/syscall.h>" 
    } 

    /p_syscall_meta/ { 
        syscall = substr($NF, 19); 
        printf "SYS_%s: \"%s\",\n", syscall, syscall 
    }
    ' /proc/kallsyms | \
        gcc -E -P - |
        grep -P "^\d+"
)
echo "nr_name = {" > "$script_d/syscallmap.py"
echo "$dict" >> "$script_d/syscallmap.py"
echo "}" >> "$script_d/syscallmap.py"

# Start the tracing program that will collect the system call time per thread

sudo bpftrace "$script_d/syscall-time.bt" $1 | python "$script_d/parse-syscall-time.py"

import sys
from syscallmap import nr_name
import re

thread_syscalltime = {}
TOTAL_TIME = None


with open("syscalltime.csv", "w") as f:
    f.write("tid,syscall,total_time_share\n")
    for line in sys.stdin:
        match = re.match(r"@\[(\d+), (\d+)\]: (\d+)", line)
        if match is not None:
            tid = match.groups()[0]
            syscall = int(match.groups()[1])
            syscall_time = int(match.groups()[2])
            if TOTAL_TIME is None:
                raise Exception()
            f.write(f"{tid},{nr_name[syscall]},{syscall_time/TOTAL_TIME}\n")
            continue

        match = re.match(r"@total_time: (\d+)", line)
        if match is not None:
            TOTAL_TIME = int(match.groups()[0])
            continue

        print(line.rstrip())

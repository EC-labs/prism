To check Prism's resource usage, you can run the following command:
```bash 
top -d 1 -H -p "$(ps -ef | grep -E 'target/.*metric-collector|bpftrace' | head -n -1 | awk '{print $2}' | paste -s -d ,)"
```

```bash
sudo cat /sys/kernel/debug/tracing/available_filter_functions
```

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

```bash
cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --pids 1
```

Filter on packets that contain our magic
```bash
sudo tcpdump -i any -n '(tcp dst port 9000) and (tcp[12] = 0xdb)'
```

```bash
sudo crictl inspect $(sudo crictl ps 2>/dev/null | grep recommendation | awk '{print $1}') | grep pid
```

```bash
sudo iptables -t raw -I OUTPUT -p tcp -j CT --notrack
```

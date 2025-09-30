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
RUST_LOG=info cargo run -r -p metric-collector --config 'target."cfg(all())".runner="sudo -E"' -- --machine-id 1 --pids 1
```

Filter on packets that contain our magic
```bash
sudo tcpdump -i any -n '(tcp dst port 9000) and (tcp[12] = 0xdb)'
```

```bash
sudo crictl inspect "$(sudo crictl ps 2>/dev/null | grep adservice | awk "{print \$1}")" 2>/dev/null | jq ".info.pid"
```

```bash
bpftool map dump id 184 | head -n -1 | awk '{printf "%s %s %s %s %s %s %s %s %s\n", $2, $3, $4, $5, $6, $7, $8, $9}' | xargs -I @ bash -c 'bpftool map delete id 184 key hex @'
```

```bash
sudo iptables -t raw -I OUTPUT -p tcp -j CT --notrack
```

Disable tcp checksum offloading:
```bash
sudo ethtool -K wlp0s20f3 tx-checksumming off
```

Run bpftrace with manually unpacked kernel headers [link](https://github.com/bpftrace/bpftrace/issues/3255):
```bash
modprobe kheaders
tar -xf /sys/kernel/kheaders.tar.xz
sudo BPFTRACE_KERNEL_SOURCE="/path/to/unpacked/headers" bpftrace runqlat.bt
```

wireshark filter such that tcp_len is greater than 0
```
(ip.proto==6) and (ip.src == 172.18.0.3) and (tcp.len > 0)
```

Create an ipv6 socket that can also receive ipv4 connections:
```bash
socat tcp6-listen:3000,reuseaddr -
```

```bash
tc filter show dev lo egress
```

Command to get resource usage per cgroup:
```bash
systemd-cgtop --depth 10
```

Command to copy the latest prism data from the 3 vms:
```bash
echo 'vm1\nvm2\nvm3' | xargs -I @ bash -c 'scp @:/home/ubuntu/prism/data/"$(ssh @ "ls -Art /home/ubuntu/prism/data | tail -n 1")" ./media/vm@.db3'
```

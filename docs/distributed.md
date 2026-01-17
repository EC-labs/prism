# Overview

This document is part of a demo conducted to illustrate Prism auto-discovering and monitoring a microservice application deployed on a kubernetes cluster with 3 nodes. Almost all commands can be run unmodified, except for those that have a note indicating otherwise.

# Pre-requisites

1. **Distributed** k8s cluster
1. A machine with ssh access to each k8s node
1. root access to each k8s node
1. `kubectl` and `nix` installed on the same machine that has ssh access from where the following commands will be executed

> Note: The commands executed in this tutorial can all be done from a single machine, as long as: it has ssh access to the nodes; kubectl is configured to access the distributed k8s cluster.

# Start Microservice Environment

```bash
kubectl apply -f "https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/refs/heads/main/release/kubernetes-manifests.yaml"
```

# Start Prism

There are 2 conditions that have to be met to successfully map a distributed system's dependency graph with Prism: 

* Ensure we start Prism on all machines that run any service that is part of the application;
* At least one of the Prism agents initiated has to be bootstrapped with a process identifier (`pid`) that belongs to the application.

The last condition provides Prism with the starting process from which it will discover all other process that are directly or indirectly connected to it. 

Get the pods currently deployed in our default namespace which should contain the online boutique services: 

```bash
kubectl get pods -o wide
# NAME                                     READY   STATUS    RESTARTS        AGE   IP            NODE               NOMINATED NODE   READINESS GATES
# adservice-dbd9db68f-w4gmb                1/1     Running   0               18h   10.244.0.21   ip-172-31-31-167   <none>           <none>
# cartservice-7d446cd6cd-rn4xh             1/1     Running   0               18h   10.244.0.19   ip-172-31-31-167   <none>           <none>
# checkoutservice-b45957b77-z5l2p          1/1     Running   0               18h   10.244.1.27   ip-172-31-27-25    <none>           <none>
# currencyservice-768c464f5-p29rh          1/1     Running   3 (3h27m ago)   18h   10.244.1.31   ip-172-31-27-25    <none>           <none>
# emailservice-5756ddcbb5-6wmpt            1/1     Running   0               18h   10.244.2.12   ip-172-31-25-17    <none>           <none>
# frontend-6d47d98676-h698l                1/1     Running   0               18h   10.244.1.29   ip-172-31-27-25    <none>           <none>
# loadgenerator-645dcc4d68-bqzvp           1/1     Running   0               18h   10.244.2.15   ip-172-31-25-17    <none>           <none>
# paymentservice-69c9f447bf-67dzv          1/1     Running   3 (99m ago)     18h   10.244.1.28   ip-172-31-27-25    <none>           <none>
# productcatalogservice-66db9f456f-25zzj   1/1     Running   0               18h   10.244.2.14   ip-172-31-25-17    <none>           <none>
# recommendationservice-5767cf4d97-wjq4q   1/1     Running   0               18h   10.244.2.13   ip-172-31-25-17    <none>           <none>
# redis-cart-c8ff86559-g5sct               1/1     Running   0               18h   10.244.1.30   ip-172-31-27-25    <none>           <none>
# shippingservice-7c44749569-kl8gx         1/1     Running   0               18h   10.244.0.20   ip-172-31-31-167   <none>           <none>
```

From the above output, we can see that our services are deployed on three different nodes, `ip-172-31-31-167`, `ip-172-31-27-25` and `ip-172-31-25-17`. We now select the bootstrap process, which can be any of the displayed services. We will select the `adservice-dbd9db68f-w4gmb`. 

To get the `pid` of the process running within this pod, run (**don't forget to replace the parameterized `<adservice-node>`**): 

```bash
ssh <adservice-node> -t 'sudo crictl inspect "$(sudo crictl ps 2>/dev/null | grep adservice | awk "{print \$1}")" 2>/dev/null | jq ".info.pid"'
```

> Note: The previous command may differ if your container runtime is not containerd


<details>
    <summary>Example</summary>

    ssh ip-172-31-31-167 -t 'sudo crictl inspect "$(sudo crictl ps 2>/dev/null | grep adservice | awk "{print \$1}")" 2>/dev/null | jq ".info.pid"'   

</details>


Open up a terminal per node, and we can start Prism on each node:
```bash
ssh <node-1> -t 'docker run \
    --rm -it --privileged \
    -e RUST_LOG=info \
    --pid host \
    -v ./cdata:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --name prism \
    dclandau/prism --machine-id 1'
```

<details>
    <summary>Example</summary>

    ssh ip-172-31-27-25 -t 'docker run \
        --rm -it --privileged \
        -e RUST_LOG=info \
        --pid host \
        -v ./cdata:/data \
        -v /sys/fs/cgroup:/sys/fs/cgroup \
        -v /sys/kernel/tracing:/sys/kernel/tracing \
        -v /sys/kernel/debug:/sys/kernel/debug \
        --name prism \
        dclandau/prism --machine-id 1'

</details>

```bash
ssh <node-2> -t 'docker run \
    --rm -it --privileged \
    -e RUST_LOG=info \
    --pid host \
    -v ./cdata:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --name prism \
    dclandau/prism --machine-id 2'
```

<details>
    <summary>Example</summary>
    
    ssh ip-172-31-25-17 -t 'docker run \
        --rm -it --privileged \
        -e RUST_LOG=info \
        --pid host \
        -v ./cdata:/data \
        -v /sys/fs/cgroup:/sys/fs/cgroup \
        -v /sys/kernel/tracing:/sys/kernel/tracing \
        -v /sys/kernel/debug:/sys/kernel/debug \
        --name prism \
        dclandau/prism --machine-id 2'

</details>

Note that the following command is run in the adservice-node, and that we pass the pid we extracted above such that this Prism agent can be bootstrapped with adservice's pid.

```bash
ssh <adservice-node> -t 'docker run \
    --rm -it --privileged \
    -e RUST_LOG=info \
    --pid host \
    -v ./cdata:/data \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    --name prism \
    dclandau/prism --machine-id 3 --pids <adservice-pid>'
```

<details>
    <summary>Example</summary>

    ssh ip-172-31-31-167 -t 'docker run \
        --rm -it --privileged \
        -e RUST_LOG=info \
        --pid host \
        -v ./cdata:/data \
        -v /sys/fs/cgroup:/sys/fs/cgroup \
        -v /sys/kernel/tracing:/sys/kernel/tracing \
        -v /sys/kernel/debug:/sys/kernel/debug \
        --name prism \
        dclandau/prism \
            --machine-id 3 \
            --pids "$(sudo crictl inspect "$(sudo crictl ps 2>/dev/null | grep adservice | awk "{print \$1}")" 2>/dev/null | jq ".info.pid")"'

</details>

After letting it run for approximately 30s, we can interrupt the Prism agents we started with an interrupt signal (`Ctrl-C`).

# Data Visualisation

Copy the data from the Prism agents to your laptop where you would like to analyse it: 

```bash
mkdir data; echo '<node-1>\n<node-2>\n<adservice-node>' | xargs -I @ bash -c 'scp @:/home/ubuntu/cdata/"$(ssh @ "ls -Art /home/ubuntu/cdata | tail -n 1")" ./data/@.db3'
```

> Note: The previous command may differ if the directory where the data was stored in each node is different from `/home/ubuntu/cdata`.


<details>
    <summary>Example</summary>

    mkdir data; echo 'ip-172-31-25-17\nip-172-31-27-25\nip-172-31-31-167' | xargs -I @ bash -c 'scp @:/home/ubuntu/cdata/"$(ssh @ "ls -Art /home/ubuntu/cdata | tail -n 1")" ./data/@.db3'

</details>

Run the following command to combine databases for analysis:
```
nix run .#combinedbs -- --dbs "<node-1>.db3,<node-2>.db3,<adservice-node>.db3" --result-file ./data/combined.db3
```
<details>
    <summary>Example</summary>

    nix run .#combinedbs -- --dbs "./data/ip-172-31-25-17.db3,./data/ip-172-31-27-25.db3,./data/ip-172-31-31-167.db3" --result-file "./data/combined.db3"

</details>

> Note: The previous command may differ if the local directory where you copied your data to is not `./data`.

You should now find a new file `./data/combined.db3` that can be imported to the analysis UI. To start the analysis UI, run:
```
nix run .#analysis
```

You may now explore the data Prism collected for the three nodes when bootstrapping Prism with adservice's `pid` in the adservice node. The remaining metrics collected in the other nodes are a result of Prism's automatic discovery.

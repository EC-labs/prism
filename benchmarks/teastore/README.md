# Teastore

## Setup

**The following command assume you are in the `benchmarks/teastore` directory.**
```bash
cd benchmarks/teastore
```

To start Teastore, run: 
```bash
docker compose up -d
```

Move to Prism's root directory and start tracing the webui component:
```bash
cd ../..
sudo sysctl "kernel.sched_schedstats=1"
sudo sysctl "fs.pipe-max-size=2097152"
ulimit -n 32768
cargo run -r -p metric-collector -- --pids "$(docker top teastore-webui-1 | grep /bin/java | awk '{print $2}')" >./prism_${ts}.log 2>&1 &
cd benchmarks/teastore
```

Following teastore's indications, we use locust to stress the teastore application. We start locust with the following command: 
```bash
locust -f locustfile.py,double_wave.py --processes 3
```

You now should be able to access the locust instance on your local browser through the following link [http://localhost:8089/](http://127.0.0.1:8089/).

To start the experiment, we simply change the host on locust's UI to `http://127.0.0.1:8080/tools.descartes.teastore.webui` and press start.

Upon termination, we can terminate the locust instance pressing Ctrl-C in the terminal, and we should see 2 new files `raw_users.csv` and `raw_request.csv`.

We can further process the `raw_request.csv` file to obtain the 95th percentile latency for the webui component.

## Experiment

1. Start the locust load pattern as described above

The experiment has the following artifacts:

* `containers-inspect.log`: This is the result of running `docker inspect` on all containers;
* `raw_requests.csv`: Contains the start and end times of a request, and its latency.
* `raw_users.csv`: The number of users started at a particular instant. 

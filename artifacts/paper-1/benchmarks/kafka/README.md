# Kafka

The procedure involves starting a kafka instance, start tracing it with prism, and start the producers which will produce a variable amount of load against the kafka broker, and finally start a producer scraper that will collect producer statistics from the producers.

To run the experiment, execute: 
```bash
benchmarks/kafka/run.sh
```

This will output a file `benchmarks/kafka/scrape-experiment-producer/throughput.csv` which includes the number of events sent to kafka from the producer instance each second. The throughput, i.e. the target metric, can be derived from the data in this file by calculating the difference in events each second.

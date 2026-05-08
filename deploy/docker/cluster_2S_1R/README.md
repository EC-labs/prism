**./cluster_2S_1R**

Creates a 2 shard clickhouse cluster, each shard with a single replica. The username is `cluster_user` and password is `cluster_pass`.

Start the cluster with: 
```
docker compose up -d 
```

You can connect to the clickhouse database with:
```
clickhouse-client -h localhost --port 9000 --user cluster_user --password cluster_pass
```

# MySQL

MySQL:
```bash
docker network create mysql_net
docker run -d \
  --rm \
  --name mysqldb \
  --network mysql_net \
  -e MYSQL_ROOT_PASSWORD=secret \
  -e MYSQL_DATABASE=test \
  mysql:8.0 \
  --default-authentication-plugin=mysql_native_password
```

Generate Load:
```bash
docker run --rm --network mysql_net severalnines/sysbench \
  sysbench \
  /usr/share/sysbench/oltp_read_write.lua \
  --mysql-host=mysqldb \
  --mysql-user=root \
  --mysql-password=secret \
  --mysql-db=test \
  --db-driver=mysql \
  prepare

docker run --rm --network mysql_net severalnines/sysbench \
  sysbench \
  /usr/share/sysbench/oltp_read_write.lua \
  --mysql-host=mysqldb \
  --mysql-user=root \
  --mysql-password=secret \
  --mysql-db=test \
  --db-driver=mysql \
  --threads=2 \
  --time=10 \
  run

docker run --rm --network mysql_net severalnines/sysbench \
  sysbench /usr/share/sysbench/oltp_read_write.lua \
  --mysql-host=mysql --mysql-user=root --mysql-password=secret \
  --mysql-db=test --db-driver=mysql \
  cleanup
```

# Postgres


```bash
docker network create pg
docker run --network pg --name postgres --rm -d -e POSTGRES_USER=default -e POSTGRES_PASSWORD=default postgres:14.1
```

```bash
docker run -it --rm \
  --network pg \
  postgres:14.1 \
  pgbench -h postgres -U default --initialize default

docker run -it --rm \
  --network pg \
  postgres:14.1 \
  pgbench -h postgres -U default -T 10 -c 2 default
```

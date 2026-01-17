#!/usr/bin/env python3

import duckdb
import click
import os


@click.option('--dbs', is_flag=False, metavar='<database-list>', type=click.STRING, help='Comma-seperated list of duckdb databases')
@click.option('--result-file', is_flag=False, type=click.Path(exists=False), help='File path where the combined database files should be stored')
@click.command()
def main(dbs, result_file):
    # split columns by ',' and remove whitespace
    if dbs is None:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        return

    if result_file is None:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        return

    dbs = [click.Path(exists=True).convert(db.strip(), None, None) for db in dbs.split(',')]
    res = duckdb.connect(result_file)

    for db in dbs:
        print(db)
        res.execute(f"""ATTACH '{db}' AS src""")
        tables = res.execute("SELECT table_name FROM information_schema.tables WHERE table_catalog='src'").fetchall()
        for i, (table, ) in enumerate(tables):
            if i == 0:
                res.execute("""
                    CREATE TABLE IF NOT EXISTS linux_consts AS 
                        SELECT * FROM src.linux_consts;

                    UPDATE linux_consts 
                    SET value = 2
                    WHERE const_name = 'SOCK_DGRAM' AND const_type = 'socket_type';

                    UPDATE linux_consts 
                    SET value = 1
                    WHERE const_name = 'SOCK_STREAM' AND const_type = 'socket_type';
                """)
            if table in ("linux_consts", "taskstats_view"):
                continue
            else: 
                query = f"""
                    CREATE TABLE IF NOT EXISTS {table} AS 
                        SELECT * FROM src.{table} WHERE 1=0;

                    INSERT INTO {table}
                    SELECT * FROM src.{table}
                """
                res.execute(query, [])


        res.execute("""
            CREATE OR REPLACE VIEW taskstats_view AS 
            SELECT 
                machine_id,
                ts, 
                time_diff,
                pid,
                tid,
                comm,
                run_time/time_diff as run_share, 
                rq_time/time_diff as rq_share,
                uninterruptible_time/time_diff as uninterruptible_share,
                blkio_time/time_diff as blkio_share,
                greatest((time_diff - (run_time + rq_time + uninterruptible_time))/time_diff, 0) as interruptible_share
            FROM (
                SELECT 
                    machine_id,
                    ts, 
                    epoch_ns(ts - ts_last) as time_diff,
                    pid,
                    tid, 
                    comm,
                    run_time_curr - run_time_last AS run_time,
                    rq_time_curr - rq_time_last AS rq_time,
                    uninterruptible_time_curr - uninterruptible_time_last AS uninterruptible_time,
                    blkio_time_curr - blkio_time_last AS blkio_time,
                FROM (
                    SELECT 
                        machine_id,
                        ts, 
                        lag(ts, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as ts_last,
                        pid,
                        tid, 
                        comm,
                        run_time_total as run_time_curr, 
                        lag(run_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as run_time_last,
                        rq_time_total as rq_time_curr, 
                        lag(rq_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as rq_time_last,
                        uninterruptible_total as uninterruptible_time_curr, 
                        lag(uninterruptible_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as uninterruptible_time_last,
                        blkio_time_total as blkio_time_curr, 
                        lag(blkio_time_total, 1) OVER (PARTITION BY machine_id, tid ORDER BY ts) as blkio_time_last,
                    FROM taskstats
                )
            )
            WHERE 
                time_diff IS NOT NULL;
        """)
        res.execute("""DETACH src""")


main()

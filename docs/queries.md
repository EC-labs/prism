Get completed circuit tcp sockets:
```sql
SELECT 
    hex(local_machine_id),
    local_inode_id,
    hex(remote_machine_id),
    remote_inode_id,
FROM 
    tcp_discovery
WHERE
    remote_machine_id <> 0
    AND remote_inode_id <> 0;
```

Get pids that wrote to sockets:
```sql
SELECT 
    DISTINCT pid, 
    inode_id 
FROM 
    vfs
WHERE 
    fs_magic = 1397703499;
```

Get the local processes that wrote to sockets:
```
WITH 
    local_sockets AS (
        SELECT 
            hex(local_machine_id),
            local_inode_id,
            hex(remote_machine_id),
            remote_inode_id,
        FROM 
            tcp_discovery
        WHERE
            remote_machine_id <> 0
            AND remote_inode_id <> 0
            AND local_machine_id = remote_machine_id
    ),
    pid_socks AS (
        SELECT 
            DISTINCT pid, 
            inode_id 
        FROM 
            vfs
        WHERE 
            fs_magic = 1397703499
    )
SELECT 
    lp.pid, 
    ls.local_inode_id,
    rp.pid,
    ls.remote_inode_id
FROM
    local_sockets ls
LEFT JOIN
    pid_socks lp /* lp = local pid */
    ON ls.local_inode_id = lp.inode_id
LEFT JOIN
    pid_socks rp /* rp = remote pid (following the tcp_discovery naming convention)*/
    ON ls.remote_inode_id = rp.inode_id;
```

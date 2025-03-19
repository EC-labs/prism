#ifndef __MUXIO_H
#define __MUXIO_H

#define MAX_ENTRIES 8192
#define SAMPLE_MAX_ENTRIES MAX_ENTRIES
#define PENDING_MAX_ENTRIES MAX_ENTRIES
#define SAMPLES 10

#define POLL_START  0x0
#define POLL_END    0x1
#define POLL_REGISTER_FILE  0x2
#define EPOLL_START 0x3
#define EPOLL_END   0x4
#define EPOLL_INSERT_FILE   0x5
#define EPOLL_REMOVE_FILE   0x6

struct poll_start_event {
    __u8 event;
    __u64 tgid_pid;
    __u64 ts;
};

struct poll_end_event {
    __u8 event;
    __u64 tgid_pid;
    __u64 ts;
};

struct poll_register_file_event {
    __u8 event;
    __u32 magic;
    __u32 i_rdev;
    __u64 tgid_pid;
    __u64 i_ino;
    __u64 ts;
};

struct epoll_files_key {
    __u32 magic;
    __u32 i_rdev;
    __u64 i_ino;
    __u64 ep_address;
};

struct epoll_register_file_event {
    __u8 event;
    __u32 magic;
    __u32 i_rdev;
    __u64 i_ino;
    __u64 ep_address;
    __u64 ts;
};

struct epoll_start_event {
    __u8 event;
    __u64 tgid_pid;
    __u64 ep_address;
    __u64 ts;
};

struct epoll_end_event {
    __u8 event;
    __u64 tgid_pid;
    __u64 ep_address;
    __u64 ts;
};

#endif /* __MUXIO_H */

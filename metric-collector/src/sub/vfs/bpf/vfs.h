/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __VFS_H
#define __VFS_H

#define MAX_ENTRIES 8192
#define SAMPLE_MAX_ENTRIES MAX_ENTRIES
#define PENDING_MAX_ENTRIES MAX_ENTRIES
#define SAMPLES 10

#define READ 0
#define WRITE 0

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

struct bri {
	__u8 s_id[32];
	__u64 i_ino;
	__u32 i_rdev;
};



struct inflight_key {
	__u64 tgid_pid;
};

struct inflight_value {
	__u64 ts;
	struct bri bri;
};

struct granularity {
	__u32 tgid;
    __u32 pid;
	struct bri bri;
	__u8 dir;
};

struct stats {
	__u64 ts_s;
	__u64 total_time;
	__u32 total_requests;
	__u32 hist[8];
};

struct to_update_key {
	__u64 ts;
	struct granularity granularity;
};


#endif /* __VFS_H */

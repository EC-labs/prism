#ifndef _CONSTS_H
#define _CONSTS_H

#include <asm/types.h>

#define MAX_ENTRIES 8192
#define SAMPLE_MAX_ENTRIES MAX_ENTRIES
#define PENDING_MAX_ENTRIES MAX_ENTRIES
#define SAMPLES 10
#define MTU 1500

#define AIO_GETEVENTS 0
#define AIO_SUBMIT 1

static __u8 truth = 1;
static __u8 z8 = 0;
static __u64 z64 = 0;
static __u32 z32 = 0;

#endif /* _CONSTS_H */

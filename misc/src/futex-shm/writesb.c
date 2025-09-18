// Basic userspace handshake using futexes, for two processes.
//
// Eli Bendersky [http://eli.thegreenplace.net]
// This code is in the public domain.
#include <errno.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

// The C runtime doesn't provide a wrapper for the futex(2) syscall, so we roll
// our own.
int futex(int* uaddr, int futex_op, int val, const struct timespec* timeout,
          int* uaddr2, int val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

// Waits for the futex at futex_addr to have the value val, ignoring spurious
// wakeups. This function only returns when the condition is fulfilled; the only
// other way out is aborting with an error.
void wait_on_futex_value(int* futex_addr, int val) {
  struct timespec timeout = {0};
  timeout.tv_sec = 10;

  while (1) {

    if (*futex_addr == val) {
        return;
    }

    int futex_rc = futex(futex_addr, FUTEX_WAIT, *futex_addr, &timeout, NULL, 0);
    if (futex_rc == -1) {
      if (errno != EAGAIN) {
        perror("futex");
        exit(1);
      }
    } else if (futex_rc == 0) {
        continue;
    } else {
        abort();
    }
  }
}

// A blocking wrapper for waking a futex. Only returns when a waiter has been
// woken up.
void wake_futex_blocking(int* futex_addr) {
  while (1) {
    int futex_rc = futex(futex_addr, FUTEX_WAKE, 1, NULL, NULL, 0);
    if (futex_rc == -1) {
      perror("futex wake");
      exit(1);
    } else if (futex_rc > 0) {
      return;
    }
  }
}

int main(int argc, char** argv) {
    int *shared_data;
    char shmpath[] = "/futexshm";
    int fd = shm_open(shmpath, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd == -1) {
        perror("shm_open");
        exit(1);
    }

    if (ftruncate(fd, sizeof(int)) == -1) {
        perror("ftruncate");
        exit(1);
    }
        
    shared_data = mmap(NULL, sizeof(*shared_data), 
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared_data == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    printf("child shared pointer %p\n", shared_data);

    for (int i = 0; i < 100000; i++) {
        printf("child waiting for A\n");
        wait_on_futex_value(shared_data, 0xA);

        struct timespec sleep_time = {0}, remaining;
        sleep_time.tv_nsec = 10000000;
        nanosleep(&sleep_time, &remaining);
        printf("child writing B\n");
        // Write 0xB to the shared data and wake up parent.
        *shared_data = 0xB;
        wake_futex_blocking(shared_data);
    }

  return 0;
}

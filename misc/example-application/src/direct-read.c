#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>


void direct_read() {
    const char *filename = "/etc/passwd";
    const size_t buffer_size = 4096;  // Adjust the buffer size as needed
    char *buffer;
    int file_descriptor;

    // Allocate memory for the buffer with O_DIRECT alignment
    if (posix_memalign((void **)&buffer, 512, buffer_size) != 0) {
        perror("posix_memalign");
        exit(EXIT_FAILURE);
    }

    // Open the file with O_DIRECT flag
    file_descriptor = open(filename, O_RDONLY | O_DIRECT);
    if (file_descriptor == -1) {
        perror("open");
        free(buffer);
        exit(EXIT_FAILURE);
    }

    struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 1000000,
    };
    for (ssize_t i=0; i<10000; i++) {

        ssize_t bytes_read = read(file_descriptor, buffer, buffer_size);
        if (bytes_read == -1) {
            perror("read");
            free(buffer);
            close(file_descriptor);
            exit(EXIT_FAILURE);
        }
        lseek(file_descriptor, 0, SEEK_SET);
        // nanosleep(&interval, &interval);
    }
}

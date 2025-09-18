#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("test", O_CREAT | O_SYNC | O_WRONLY);
    if (fd < 0) {
        perror("open");
    }
    char *c = "This is my message\n";

    for(int i=0; i<100000000000; i++) {
        write(fd, c, 19);
        lseek(fd, 0, SEEK_SET);
    }

}

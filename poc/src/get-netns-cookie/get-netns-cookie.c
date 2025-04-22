#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    printf("%d\n", sock);

    uint64_t optval;
    uint64_t optlen = sizeof(optval);
    int ret = getsockopt(sock, SOL_SOCKET, SO_NETNS_COOKIE, &optval, (socklen_t *) &optlen);
    if (ret < 0) {
        printf("Failed: %d\n", ret);
    }
    printf("cookie: %lu\n", optval);

    close(sock);
    return 0;
}

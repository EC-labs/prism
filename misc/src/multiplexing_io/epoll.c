#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/epoll.h>

#define MAX_EVENTS 10

int main() {
    int svc_fd; 
    if ((svc_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    int svc_flags = fcntl(svc_fd, F_GETFL);
    if (svc_flags < 0) {
        perror("get flags");
        exit(1);
    }

    if (fcntl(svc_fd, F_SETFL, svc_flags | O_NONBLOCK) < 0) {
        perror("set O_NONBLOCK");
        exit(1);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(svc_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(svc_fd, 0) < 0) {
        perror("listen");
        exit(1);
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create");
        exit(1);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = svc_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, svc_fd, &ev) < 0) {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    printf("start sleep\n");
    sleep(60);

    printf("start epoll_wait\n");
    int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    printf("epoll_wait returned: %d\n", nfds);
    return 0;
}

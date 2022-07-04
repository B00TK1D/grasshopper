#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/if_ether.h>
 
int main(void)
{
    unsigned char buf[1500];
    int fd, n;
 
    if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        fprintf(stderr, "failed to initialise socket\n");
        return EXIT_FAILURE;
    }
    while ((n = read(fd, buf, sizeof buf)) > 0)
        fwrite(buf, 1, n, stdout);
    close(fd);
    return EXIT_FAILURE;
}
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include "ft_traceroute.h"


bool parse(int argc, char ** argv, struct s_ft_traceroute * tr) {
    tr->prog_name = argv[0];
    tr->host_name = "google.com";
    return true;
}

bool init(struct s_ft_traceroute * tr) {
    memset(&tr->serv_addr, 0, sizeof(tr->serv_addr));
    if (!dns_lookup(tr))
        return false;
    // open udp and icmp sockets
    tr->udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tr->udp_sockfd < 0) {
        fprintf(stderr, "%s: could not open socket: %s\n", tr->prog_name, strerror(errno));
        return false;
    }
    tr->icmp_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (tr->icmp_sockfd < 0) {
        fprintf(stderr, "%s: could not open socket: %s\n", tr->prog_name, strerror(errno));
        close(tr->udp_sockfd);
        return false;
    }
    for (int i = 0 ; i < 32 ; i++)
        tr->udp_data[i] = 'A' + i;
    tr->serv_addr.sin_family = AF_INET;
    tr->serv_addr.sin_port = htons(33434);  // Set server port
    tr->serv_addr.sin_addr = ((struct sockaddr_in)tr->serv_addr).sin_addr;
    return true;
}

bool read_loop(struct s_ft_traceroute * tr) {
    struct s_icmp_hdr hdr;

    // if icmp packet type 11 code 0 
        // measure response time
        // reverse dns to get hostname
    // else if no data received
        // print *
}

int main(int argc, char ** argv) {
    // on VM, traceroute -V :
    // Modern traceroute for Linux, version 2.1.2
    // Copyright (c) 2016  Dmitry Butskoy,   License: GPL v2 or any later
    struct s_ft_traceroute tr;

    // parse arguments
    if (!parse(argc, argv, &tr))
        return 1;
    // init
    init(&tr);
    for (tr.current_TTL = 1 ; tr.current_TTL <= DFLT_MAX_HOPS ; tr.current_TTL++) {
        setsockopt(tr.udp_sockfd, IPPROTO_IP, IP_TTL, &tr.current_TTL, sizeof(tr.current_TTL));
        for (tr.probe_number = 0 ; tr.probe_number < DFLT_PROBE_NUMBER ; tr.probe_number++) {
            // send over udp
            if (sendto(tr.udp_sockfd, tr.udp_data, sizeof(tr.udp_data), 0, &(struct sockaddr)tr.serv_addr, sizeof(tr.serv_addr)) == -1) {
                fprintf(stderr, SEND_ERROR);
                close(tr.icmp_sockfd);
                close(tr.udp_sockfd);
                exit(1);
            }
            // receive data over icmp
            read_loop(&tr);
            tr.serv_addr.sin_port = tr.serv_addr.sin_port++;
        }
    }
    printf("Hello world\n");
    return 0;
}
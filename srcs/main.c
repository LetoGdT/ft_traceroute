#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include "libft.h"
#include "ft_traceroute.h"

volatile sig_atomic_t sigint_occured;

void sigint_handler(int sig) {
    sigint_occured = true;
}

void parse(int argc, char ** argv, struct s_ft_traceroute * tr) {
    ft_bzero(tr, sizeof(*tr));
    tr->prog_name = argv[0];
    tr->host_name = "google.com";
}

void init(struct s_ft_traceroute * tr) {
    sigint_occured = false;
    signal(SIGINT, sigint_handler);
    ft_bzero(&tr->serv_addr, sizeof(tr->serv_addr));
    if (!dns_lookup(tr)) {
        fprintf(stderr, DNS_LKUP_ERR);
        exit(1);
    }
    // open udp and icmp sockets
    tr->udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tr->udp_sockfd < 0) {
        fprintf(stderr, "%s: could not open socket: %s\n", tr->prog_name, strerror(errno));
        exit(1);
    }
    tr->icmp_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (tr->icmp_sockfd < 0) {
        fprintf(stderr, "%s: could not open socket: %s\n", tr->prog_name, strerror(errno));
        close(tr->udp_sockfd);
        exit(1);
    }
    for (int i = 0 ; i < sizeof(tr->udp_data) ; i++)
        tr->udp_data[i] = 'A' + i;
    tr->serv_addr.sin_family = AF_INET;
    tr->serv_addr.sin_port = htons(FIRST_PORT);  // Set server port
    tr->serv_addr.sin_addr = ((struct sockaddr_in)tr->serv_addr).sin_addr;
}

bool verify_icmp_header(const char * const recv_buff, const struct s_ft_tracerout const * tr) {
    struct s_icmp_hdr hdr;

    // Extract icmp header from received packet
    ft_memcpy(&hdr, recv_buff + (recv_buff[0] && 0xF) * 4, sizeof(hdr));
    return hdr.type == 11 && hdr.code == 0;
}

bool read_loop(struct s_ft_traceroute * tr) {
    struct timeval timeout;
    fd_set read_fs;
    double timediff;
    int ready_count;
    char recv_buff[1024];
    char * remote_host_name;
    char * remote_host_address;
    struct in_addr addr;

    // set the timeout to wait at most 1 second
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    while (timeout.tv_sec + timeout.tv_usec > 0) {
        FD_ZERO(&read_fs);
        FD_SET(tr->icmp_sockfd, &read_fs);
        // wait for data to come back on the icmp socket
        ready_count = select(tr->icmp_sockfd + 1, &read_fs, NULL, NULL, &timeout);
        if (ready_count < 0) {
            // Case where user requested the program stop by CTRL-C
            if (errno == EINTR) {
                close(tr->udp_sockfd);
                close(tr->icmp_sockfd);
                exit(0);
            }
            fail(tr, print_strerror);
        }
        // Case where the timeout expired and no data was received
        else if (ready_count == 0 || !FD_ISSET(tr->udp_sockfd, &read_fs)) {
            ////******* */
            printf("* "); // ça c'est bof bof, à revoir
            return false;
        }
        // Case where data was received
        ft_bzero(recv_buff, sizeof(recv_buff));
        if (read(tr->udp_sockfd, recv_buff, sizeof(recv_buff)) == -1)
            fail(tr, print_strerror);
        // Verify that we have received the correct packet
        if (!verify_icmp_header(recv_buff, tr))
            continue ;
        // Extract source address from ip header
        ft_memcpy(&addr.s_addr, recv_buff + 12, 4);
        remote_host_address = inet_ntoa(addr);
        // Perform reverse DNS to get hostname of responding server
        remote_host_name = reverse_dns_lookup(recv_buff);

    }
    // if icmp packet type 11 code 0 
        // measure response time
        // reverse dns to get hostname
    // else if no data received
        // print *
}

void fail(const struct s_ft_traceroute * tr, enum error_type error) {
    switch (error) {
        case time_error:
            fprintf(stderr, TIME_ERROR);
            break;
        case send_error:
            fprintf(stderr, SEND_ERROR);
            break;
        case print_strerror:
            fprintf(stderr, PRINT_STRERROR);
            break;
    }
    close(tr->icmp_sockfd);
    close(tr->udp_sockfd);
    exit(1);
}

int main(int argc, char ** argv) {
    // on VM, traceroute -V :
    // Modern traceroute for Linux, version 2.1.2
    // Copyright (c) 2016  Dmitry Butskoy,   License: GPL v2 or any later
    struct s_ft_traceroute tr;

    // parse arguments
    parse(argc, argv, &tr);
    // init
    init(&tr);
    for (tr.current_TTL = 1 ; tr.current_TTL <= DFLT_MAX_HOPS ; tr.current_TTL++) {
        setsockopt(tr.udp_sockfd, IPPROTO_IP, IP_TTL, &tr.current_TTL, sizeof(tr.current_TTL));
        for (tr.probe_number = 0 ; tr.probe_number < DFLT_PROBE_NUMBER ; tr.probe_number++) {
            // send over udp
            if (gettimeofday(&tr.send_time, NULL)) 
                fail(&tr, time_error);
            if (sendto(tr.udp_sockfd, tr.udp_data, sizeof(tr.udp_data), 0, (struct sockaddr *)&tr.serv_addr, sizeof(tr.serv_addr)) == -1) 
                fail(&tr, send_error);
            // receive data over icmp
            read_loop(&tr);
            tr.serv_addr.sin_port = tr.serv_addr.sin_port++;
        }
    }
    return 0;
}
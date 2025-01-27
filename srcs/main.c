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

void parse(int argc, char ** argv, struct s_ft_traceroute * tr) {
    ft_bzero(tr, sizeof(*tr));
    tr->prog_name = argv[0];
    if (argc != 2) {
        printf(USAGE);
        exit(1);
    }
    if (argc == 2 && ft_strncmp("--help", argv[1], 7) == 0) {
        printf(USAGE);
        exit(1);
    }
    tr->host_name = argv[1];
}

void init(struct s_ft_traceroute * tr) {
    ft_bzero(&tr->serv_addr, sizeof(tr->serv_addr));
    if (!dns_lookup(tr)) {
        fprintf(stderr, DNS_LKUP_ERR);
        exit(1);
    }
    tr->destination_reached = false;
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

bool verify_udp_and_icmp_header(char * recv_buff, const struct s_ft_traceroute * tr) {
    struct s_icmp_hdr hdr;
    uint8_t size_of_first_ip_hdr;
    uint8_t size_of_second_ip_hdr;
    uint16_t total_size_of_ip_packet;
    uint16_t dest_port;

    // Verify the checksum of the outermost ip hdr
    if (!verify_ip_checksum(recv_buff))
        return false;
    // Get size of first ip hdr, IHL, which is in the lower nibble of byte 0
    size_of_first_ip_hdr = (recv_buff[0] & 0xF) * 4;
    // Compute and verify the ICMP checksum
    ft_memcpy(&total_size_of_ip_packet, recv_buff + 2, 2);
    total_size_of_ip_packet = ntohs(total_size_of_ip_packet);
    if (!verify_icmp_checksum(recv_buff + size_of_first_ip_hdr, total_size_of_ip_packet - size_of_first_ip_hdr))
        return false;
    // Extract icmp header from received packet, which is immediately after the first ip hdr
    ft_memcpy(&hdr, recv_buff + size_of_first_ip_hdr, sizeof(hdr));
    // Verify the ICMP header is of type 'destination unreachable' or 'time exceeded, TTL expired in transit'
    if (!(hdr.type == 11 && hdr.code == 0) && !hdr.type == 3)
        return false;
    size_of_second_ip_hdr = (recv_buff[size_of_first_ip_hdr + sizeof(hdr)] & 0xF) * 4;
    // Extract destination port of the udp packet that caused the icmp packet to be sent
    ft_memcpy(&dest_port, recv_buff + size_of_first_ip_hdr + size_of_second_ip_hdr + sizeof(hdr) + 2, 2);
    return dest_port == tr->serv_addr.sin_port;
}

void print_message(const char * recv_buff, struct s_ft_traceroute * tr) {
    char * remote_host_name;
    char * remote_host_address;
    struct in_addr addr;
    struct timeval current_time;
    double timediff;

    // Get the time when the packet was received
    if (gettimeofday(&current_time, NULL)) 
        fail(tr, time_error);
    timediff = (current_time.tv_sec - tr->send_time.tv_sec) * 1000
               + ((double)(current_time.tv_usec - tr->send_time.tv_usec)) / 1000;
    // Extract responding server source address from ip header
    ft_memcpy(&addr.s_addr, recv_buff + 12, 4);
    remote_host_address = inet_ntoa(addr);
    // Check that the data is from a different host than the previous one
    if (ft_strncmp(remote_host_address, tr->previous_host_address, INET_ADDRSTRLEN) != 0) {
        // Perform reverse DNS to get hostname of responding server
        remote_host_name = reverse_dns_lookup(recv_buff);
        if (remote_host_name)
            printf(" %s (%s)", remote_host_name, remote_host_address);
        else
            printf(" %s (%s)", remote_host_address, remote_host_address);
        free(remote_host_name);
    }
    // Update the previous_host_value in tr for the next packet
    for (int i = 0 ; i < INET_ADDRSTRLEN ; i++)
        tr->previous_host_address[i] = remote_host_address[i];
    // Print the RTT
    printf(" %.3lf ms", timediff);
    // Detect if the target host has been reached
    if (ft_strncmp(tr->hostaddress, remote_host_address, INET_ADDRSTRLEN) == 0)
        tr->destination_reached = true;
}

bool read_loop(struct s_ft_traceroute * tr) {
    struct timeval timeout;
    fd_set read_fs;
    int ready_count;
    char recv_buff[1024];

    // set the timeout to wait at most 1 second
    timeout.tv_sec = DEFAULT_MAX_TIMEOUT / 1000;
    timeout.tv_usec = DEFAULT_MAX_TIMEOUT % 1000;
    while (timeout.tv_sec + timeout.tv_usec > 0) {
        FD_ZERO(&read_fs);
        FD_SET(tr->icmp_sockfd, &read_fs);
        // wait for data to come back on the icmp socket
        ready_count = select(MAX(tr->icmp_sockfd, tr->udp_sockfd) + 1, &read_fs, NULL, NULL, &timeout);
        if (ready_count < 0)
            fail(tr, print_strerror);
        // Case where the timeout expired and no data was received
        else if (ready_count == 0 || !FD_ISSET(tr->icmp_sockfd, &read_fs)) {
            printf(" *");
            return false;
        }
        // Case where data was received
        ft_bzero(recv_buff, sizeof(recv_buff));
        // Receive the data
        if (read(tr->icmp_sockfd, recv_buff, sizeof(recv_buff)) == -1)
            fail(tr, print_strerror);
        // Verify that we have received the correct packet
        if (!verify_udp_and_icmp_header(recv_buff, tr))
            continue ;
        print_message(recv_buff, tr);
        break ;
    }
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
    for (tr.current_TTL = 1 ; tr.current_TTL <= DFLT_MAX_HOPS && !tr.destination_reached; tr.current_TTL++) {
        setsockopt(tr.udp_sockfd, IPPROTO_IP, IP_TTL, &tr.current_TTL, sizeof(tr.current_TTL));
        printf(" %hu", tr.current_TTL);
        for (tr.probe_number = 0 ; tr.probe_number < DFLT_PROBE_NUMBER ; tr.probe_number++) {
            // Get current time
            if (gettimeofday(&tr.send_time, NULL)) 
                fail(&tr, time_error);
            // send over udp
            if (sendto(tr.udp_sockfd, tr.udp_data, sizeof(tr.udp_data), 0, (struct sockaddr *)&tr.serv_addr, sizeof(struct sockaddr)) == -1) 
                fail(&tr, send_error);
            // receive data over icmp
            read_loop(&tr);
            tr.serv_addr.sin_port = htons(ntohs(tr.serv_addr.sin_port) + 1);
        }
        printf("\n");
    }
    return 0;
}
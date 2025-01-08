#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H
# include <sys/types.h>
# include <sys/signal.h>
# include <sys/types.h>
# define DFLT_MAX_HOPS 30
# define DFLT_PROBE_NUMBER 3
# define TIME_ERROR "Error when retrieving the time\n"
# define SEND_ERROR "%s: Cannot send packets over socket: %s\n", argv[0], strerror(errno)

struct s_ft_traceroute {
    char *             prog_name;
    char *             host_name;
    char               hostaddress[INET_ADDRSTRLEN];
    struct sockaddr_in serv_addr;
    int                icmp_sockfd;
    int                udp_sockfd;
    uint8_t            current_TTL;
    int                probe_number;
    char               udp_data[32];
};

struct __attribute__((packed)) s_icmp_hdr {
    uint8_t        type;
    uint8_t        code;
    uint16_t       checksum;
    uint16_t       id;
    uint16_t       sequence;
};


bool    dns_lookup(struct s_ft_traceroute *tr);
char *  reverse_dns_lookup(char * const raw_pkt);

#endif
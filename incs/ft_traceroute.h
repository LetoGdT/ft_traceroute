#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H
# include <sys/types.h>
# include <sys/signal.h>
# include <sys/types.h>
# define DFLT_MAX_HOPS 30
# define DFLT_PROBE_NUMBER 3
# define TIME_ERROR "Error when retrieving the time\n"

struct s_ft_traceroute {
    char *             prog_name;
    char *             canon_name;
    char               hostaddress[INET_ADDRSTRLEN];
    struct sockaddr    serv_addr;
    struct sockaddr_in destination_server;
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
int     fill_icmp_pkt(struct s_icmp_pkt *pkt, struct s_ft_traceroute const * tr);

#endif
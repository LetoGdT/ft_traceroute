#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H
# include <sys/types.h>
# include <sys/signal.h>
# include <sys/types.h>
# include <sys/time.h>
# define DFLT_MAX_HOPS 30
# define DFLT_PROBE_NUMBER 3
# define FIRST_PORT 33434
# define DNS_LKUP_ERR "%s: %s: Name or service not known\n", tr->prog_name, tr->host_name
# define TIME_ERROR "Error when retrieving the time\n"
# define SEND_ERROR "%s: Cannot send packets over socket: %s\n", tr->prog_name, strerror(errno)
# define PRINT_STRERROR "%s: %s\n", tr->prog_name, strerror(errno)

enum error_type {
    time_error,
    send_error,
    print_strerror
};

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
    struct timeval     send_time;
    char               previous_host_address[INET_ADDRSTRLEN];
};

struct __attribute__((packed)) s_icmp_hdr {
    uint8_t        type;
    uint8_t        code;
    uint16_t       checksum;
    uint16_t       id;
    uint16_t       sequence;
};


bool   dns_lookup(struct s_ft_traceroute *tr);
char * reverse_dns_lookup(char * const raw_pkt);
void   parse(int argc, char ** argv, struct s_ft_traceroute * tr);
void   init(struct s_ft_traceroute * tr);
bool   read_loop(struct s_ft_traceroute * tr);
void   fail(const struct s_ft_traceroute * tr, enum error_type error);
#endif
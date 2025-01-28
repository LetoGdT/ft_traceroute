#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H
# include <sys/types.h>
# include <sys/types.h>
# include <sys/time.h>
# include <stdbool.h>
# include <arpa/inet.h>
# define DFLT_MAX_HOPS 30
# define DFLT_PROBE_NUMBER 3
# define FIRST_PORT 33434
# define DEFAULT_MAX_TIMEOUT 1000
# define DNS_LKUP_ERR "%s: Name or service not known\nCannot handle \"host\" cmdline arg `%s' on position 1 (argc 1)\n", tr->host_name, tr->host_name
# define TIME_ERROR "Error when retrieving the time\n"
# define SEND_ERROR "%s: Cannot send packets over socket: %s\n", tr->prog_name, strerror(errno)
# define PRINT_STRERROR "%s: %s\n", tr->prog_name, strerror(errno)
# define MAX(A, B) ((A > B)?A:B)
# define USAGE "Usage:\n\
  %s [--help] host\n\
Options:\n\
  --help            Read this help and exit\n\
Arguments:\n\
+     host          The host to traceroute to\n", argv[0]

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
    bool               destination_reached;
};

struct __attribute__((packed)) s_icmp_hdr {
    uint8_t        type;
    uint8_t        code;
    uint16_t       checksum;
    uint32_t       unused;
};


bool   dns_lookup(struct s_ft_traceroute *tr);
char * reverse_dns_lookup(const char * raw_pkt);

void   parse(int argc, char ** argv, struct s_ft_traceroute * tr);
void   init(struct s_ft_traceroute * tr);
bool   read_loop(struct s_ft_traceroute * tr);
bool   verify_udp_and_icmp_header(char * recv_buff, const struct s_ft_traceroute * tr);
void   print_message(const char * recv_buff, struct s_ft_traceroute * tr);
void   fail(const struct s_ft_traceroute * tr, enum error_type error);
bool   verify_icmp_checksum(unsigned char * ICMP_pkt, size_t size);
bool   verify_ip_checksum(void *ip_packet);
#endif
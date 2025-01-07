#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include "ft_traceroute.h"

bool dns_lookup(struct s_ft_traceroute *tr) {
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags |= AI_CANONNAME;
    if(getaddrinfo (tr->canon_name, NULL, &hints, &result)) 
        return false;
    tr->serv_addr = *result->ai_addr;
    freeaddrinfo(result);
    if (!inet_ntop(AF_INET, &(((struct sockaddr_in*)&tr->serv_addr)->sin_addr), tr->hostaddress, INET_ADDRSTRLEN))
    {
        fprintf(stderr, "%s\n", strerror(errno));
        return false;
    }
    return true;
}

char* reverse_dns_lookup(char * const raw_pkt) {
    struct sockaddr_in addr;
    char hostname[1024];

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    memcpy(&addr.sin_addr, raw_pkt + 12, 4);
    if (getnameinfo((struct sockaddr*)&addr, sizeof(addr), hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD))
        return NULL;
    return strdup(hostname);
}

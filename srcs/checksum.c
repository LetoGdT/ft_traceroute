#include <sys/types.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "libft.h"

bool verify_icmp_checksum(unsigned char * ICMP_pkt, size_t size) {
    size_t i;
    u_int32_t checksum;
    u_int16_t old_checksum;

    // Copy the old checksum
    ft_memcpy(&old_checksum, ICMP_pkt + 2, 2);
    old_checksum = ntohs(old_checksum);
    // Set the checksum field in the header to 0
    ICMP_pkt[2] &= 0x0;
    ICMP_pkt[3] &= 0x0;

    i = 0;
    checksum = 0;
    while (i + 1 < size) {
        checksum += (ICMP_pkt[i] << 8) + ICMP_pkt[i + 1];
        i += 2;
    }
    // Special case for when the data has an odd length
    // We add an empty byte at the end of the array
    if (size % 2 == 1)
        checksum += ICMP_pkt[i] << 8;
    // The sum is supposed to be using one's complement, but the
    // machine uses two's complement, so we need to add the
    // overflow of the short int
    checksum = ~(checksum + (checksum >> 16)) & 0xffff;
    // Store the checksum in the ICMP header
    ICMP_pkt[2] = checksum >> 8;
    ICMP_pkt[3] = checksum & 0xff;
    return old_checksum == (u_int16_t)checksum;
}

bool verify_ip_checksum(void *ip_packet) {
    u_int32_t sum = 0;
    u_int16_t *data = (u_int16_t *)ip_packet;
    int len = ((data[0]&0x0f)) * 4;
    
    // Sum all 16-bit words
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    // Add any remaining byte (if length is odd)
    if (len == 1) {
        sum += *(u_int8_t *)data;
    }
    // Fold 32-bit sum to 16 bits (one's complement)
    sum = (sum >> 16) + (sum & 0xFFFF);
    // Verify checksum is valid
    return sum^0xFFFF == 0;
}
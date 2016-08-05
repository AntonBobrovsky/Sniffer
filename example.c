#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <linux/ip.h>
#include <ctype.h>
#include <linux/udp.h>

#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5
#define HEXDUMP_HEXSTUFF_PER_LINE (HEXDUMP_HEXSTUFF_PER_SHORT*HEXDUMP_SHORTS_PER_LINE)

void ascii_print_with_offset(register const u_char *cp, register u_int length, register u_int oset);
void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
u_short handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_udp(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_ip(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_tcp(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, u_int16_t len);

int main(int argc, char *argv[]) {
    struct in_addr addr;

    /*Определяем интерфейс, который будем слушать*/
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(-1);
    }

    pcap_t *handle;
    bpf_u_int32 net;// IP адрес нашего интерфейса
    bpf_u_int32 mask;// Сетевая маска нашего интерфейса

    /*возвращает сетевой адрес и маску сети для устройства*/
    pcap_lookupnet(dev, &net, &mask, errbuf);

    printf("DEVICE: %s\n", dev);
    addr.s_addr = net;
    printf("NET: %s\n", inet_ntoa(addr));
    addr.s_addr = mask;
    printf("MASK: %s\n", inet_ntoa(addr));

    /*создание сессии перехвата трафика*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(-1);
    }

    pcap_loop(handle, -1, callback, NULL);
    pcap_close(handle);

    return 0;
}

void ascii_print_with_offset(register const u_char *cp, register u_int length, register u_int oset) {
    register u_int i = 0;
    register int s1, s2;
    register int nshorts;
    char hexstuff[HEXDUMP_SHORTS_PER_LINE * HEXDUMP_HEXSTUFF_PER_SHORT + 1], *hsp;
    char asciistuff[HEXDUMP_BYTES_PER_LINE + 1], *asp;

    nshorts = length / sizeof(u_short);
    hsp = hexstuff;
    asp = asciistuff;

    while(--nshorts >= 0) {
        s1 =* cp++;
        s2 =* cp++;
        (void)snprintf(hsp, sizeof(hexstuff)-(hsp-hexstuff)," %02x%02x", s1, s2);
        hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
        *(asp++) = (isgraph(s1) ? s1 : '.');
        *(asp++) = (isgraph(s2) ? s2 : '.');

        if(++i >= HEXDUMP_SHORTS_PER_LINE) {
            *hsp =* asp = '\0';
            printf("\n0x%04x\t%-*s\t%s", oset, HEXDUMP_HEXSTUFF_PER_LINE, hexstuff, asciistuff);
            i = 0;
            hsp = hexstuff;
            asp = asciistuff;
            oset += HEXDUMP_BYTES_PER_LINE;
        }
    }
    if(length & 1) {
        s1 =* cp++;
        (void)snprintf(hsp, sizeof(hexstuff)-(hsp-hexstuff)," %02x", s1);
        hsp += 3;
        *(asp++) = (isgraph(s1) ? s1 : '.');
        ++i;
    }

    if(i > 0) {
        *hsp =* asp = '\0';
        (void)printf("\n0x%04x\t%-*s\t%s", oset, HEXDUMP_HEXSTUFF_PER_LINE, hexstuff, asciistuff);
    }
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int16_t etype = handle_ethernet(args, pkthdr, packet);
    switch (etype) {
        case ETHERTYPE_IP:
            handle_ip(args, pkthdr, packet);
            break;

        case ETHERTYPE_ARP:
            printf("\nARP\t\n\n");
            printf("***********************");
            break;

        case ETHERTYPE_REVARP:
            printf("\nReverse ARP\t\n\n");
            printf("***********************");
            break;

        case ETHERTYPE_VLAN:
            printf("\nIEEE 802.1Q VLAN\t\n\n");
            printf("***********************");
            break;

        default:
            printf("\n***********************");
    }
}

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header *eth;
    eth = (struct ether_header *) packet;

    printf("\n\nETHERNET\t\n");
    printf("\tProtocol type: %04x\n", ntohs(eth->ether_type));
    printf("\tEthernet source address: %s\n", ether_ntoa((const struct ether_addr *)&eth->ether_shost));
    printf("\tEthernet destination address: %s\n", ether_ntoa((const struct ether_addr *)&eth->ether_dhost));

    return ntohs(eth->ether_type);
}

u_short  net_checksum( void *data, size_t len ) {
    u_long sum = 0;
    u_short *dp = (u_short *)data;
    u_short sum_s;
    int words = len >> 1;

    while( words-- )
        sum += *dp ++;

    if( len & 1 )
        sum += *(u_char*) dp;

    sum = (ushort) sum + (sum >> 16) & 0xffff;
    sum_s = (ushort) sum + (ushort)(sum >> 16);

    return sum_s != 0xffff ? ~sum_s : sum_s;
    }

void handle_ip(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct iphdr *ip;

    ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    printf("\nIP\t\n");
    printf("\tSource: %s", inet_ntoa(*(struct in_addr*)&ip->saddr));
    printf(" Destination: %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
    printf("\n\theader length: %d\n\tid: %d\n\tTTL: %d\n\tchecksum = %d\n", ip->tot_len, ip->id, ip->ttl, ip->check);

    if (ip->protocol == IPPROTO_TCP)
        handle_tcp(args, pkthdr, packet, ip->tot_len);
    else if (ip->protocol == IPPROTO_UDP)
        handle_udp(args, pkthdr, packet);
}

void handle_udp(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct udphdr *udp;

    udp = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));

    printf("\nUDP\tsource port: %d", ntohs(udp->source));
    printf(" dest port: %d\n", ntohs(udp->dest));
    printf("\n\tlenght = %d\n\tchecksum = %d\n\n", udp->len, udp->check);
    printf("***********************");

}

void handle_tcp(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, u_int16_t len) {
    struct tcphdr* tcp;
    u_char *data;
    int iplen = sizeof(struct ether_header) + sizeof(struct iphdr);
    int tcplen = iplen + sizeof(struct tcphdr);

    tcp = (struct tcphdr *)(packet + iplen);

    printf("\nTCP\tsource port: %d", ntohs(tcp->th_sport));
    printf(" dest port: %d\n", ntohs(tcp->th_dport));
    printf("\n\tchecksum = %d\n\n", tcp->check);
    printf("***********************");

    data = (u_char *)(packet + tcplen);
    // len = len - (sizeof(struct iphdr) + sizeof(struct tcphdr));
    // ascii_print_with_offset(data, len, 0);
    // printf("\n\n");
}
